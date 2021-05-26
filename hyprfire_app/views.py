from decimal import Decimal

from django.http import HttpResponse, JsonResponse, FileResponse
from django.shortcuts import render
from pathvalidate import sanitize_filename

from hyprfire_app.filtering.packet_filter import PacketFilter
from hyprfire_app.filtering.packet_details_collector import PacketDetailsCollector

from hyprfire_app.forms import AnalyseForm
from hyprfire_app.utils.pcap import write_packets_to_file
from hyprfire_app.utils.file import get_filename_list, get_file
from hyprfire_app.utils.timestamp import validate_timestamp
from hyprfire_app.utils.validation import validate_file_path

from hyprfire.settings import BASE_DIR
from hyprfire_app.exceptions import JSONError, TimestampException
from hyprfire_app.analysis.CacheHandler import CacheHandler
import logging

from tempfile import TemporaryFile

logger = logging.getLogger(__name__)


blacklist = [
    '.gitignore'
]

logger = logging.getLogger(__name__)

def index(request):
    filenames = get_filename_list()
    if request.method == "POST":
        try:
            form = AnalyseForm(request.POST)
            if form.is_valid():
                user_file_name = form.cleaned_data['filenames']
                clean_file_name = get_file(user_file_name)
                full_file_path = f'{BASE_DIR}/pcaps/{clean_file_name}'
                window = form.cleaned_data['window']
                algorithm = form.cleaned_data['algorithm']
                analysis = form.cleaned_data['analysis']

                response = CacheHandler(full_file_path, algorithm, window, analysis)

                return render(request, 'hyprfire_app/index.html', {'form': form, 'filenames': filenames, 'graph': response})
        except ValueError as e:
            logging.exception("An Incorrect Value was passed through the CacheHandler - Cannot Process File")
            return HttpResponse(status=400, reason=str(e))

        except FileNotFoundError as e:
            logging.exception("File name/path passed through CacheHandler cannot be found - Cannot Process File")
            return HttpResponse(status=404, reason=str(e))


    else:
        form = AnalyseForm()

    return render(request, 'hyprfire_app/index.html', {'form': form, 'filenames': filenames})


def download_pcap_snippet(request, user_filename, start, end):
    """
    download_pcap_snippet

    Endpoint: /download/

    Download a snippet of pcaps from a specific file

    Parameters
    request: An HTTP GET request object provided by Django
    user_filename: the file to filter packets from
    start: an epoch-based unix timestamp identifying the first packet of the set
    end: an epoch-based unix timestamp identifying the last packet of the set

    Return
    A pcap file download which contains all packets with timestamps between start and end
    """
    if request.method != 'GET':
        logger.error(f'Invalid request method: "{request.method}"')
        return HttpResponse(status=405)

    try:

        logger.info('Processing download request')
        clean_filename = get_file(user_filename)
        file_path = validate_file_path(f'{BASE_DIR}/pcaps/{clean_filename}')
        start_timestamp = Decimal(validate_timestamp(start))
        end_timestamp = Decimal(validate_timestamp(end))

        pf = PacketFilter(file_path, start_timestamp, end_timestamp)
        packet_list = pf.get_filtered_list()

        filtered_filename = f'filtered-{clean_filename}'
        logger.info(f'Creating temporary file download for "{filtered_filename}"')
        file = TemporaryFile()
        write_packets_to_file(file, packet_list)
        file.seek(0)

        logger.info(f'Processing complete. "{filtered_filename}" sent to client')
        return FileResponse(file, as_attachment=True, filename=filtered_filename)

    except TimestampException as e:
        logger.warning(str(e))
        return HttpResponse(status=400, reason=str(e))
    except JSONError as e:
        logger.warning(str(e))
        return HttpResponse(status=400, reason=str(e))
    except FileNotFoundError as e:
        logger.warning(str(e))
        return HttpResponse(status=404, reason=str(e))
    except Exception as e:
        logger.exception(str(e))
        return HttpResponse(status=500, reason='Something went wrong.')


def collect_packet_data(request, user_filename, start, end):
    """
    collect_packet_data

    Endpoint: /collect/

    Collect specific packet details on all packets between two times

    Parameters
    request: An HTTP GET request object provided by Django
    filename: the file to collect a packet details from
    start: a unique seconds-based epoch timestamp to identify the first packet
    end: a unique seconds-based epoch timestamp to identify the last packet

    Return
    JSON containing a list of packet data dicts
    """

    if request.method != 'GET':
        logger.error(f'Invalid request method: "{request.method}"')
        return HttpResponse(status=405)

    try:

        logger.info('Processing collect request')
        user_filename = sanitize_filename(user_filename)
        clean_filename = get_file(user_filename)
        file_path = validate_file_path(f'{BASE_DIR}/pcaps/{clean_filename}')
        start_timestamp = Decimal(validate_timestamp(start))
        end_timestamp = Decimal(validate_timestamp(end))

        pf = PacketFilter(file_path, start_timestamp, end_timestamp)
        packet_list = pf.get_filtered_list()
        dc = PacketDetailsCollector(packet_list)
        packet_details = dc.get_details()

        logger.info(f'JSON of size {len(packet_details)} returned to client')
        return JsonResponse(data={'packet_data_list': packet_details})

    except TimestampException as e:
        logger.warning(str(e))
        return HttpResponse(status=400, reason=str(e))
    except JSONError as e:
        logger.warning(str(e))
        return HttpResponse(status=400, reason=str(e))
    except FileNotFoundError as e:
        logger.warning(str(e))
        return HttpResponse(status=404, reason=str(e))
    except Exception as e:
        logger.exception(str(e))
        return HttpResponse(status=500, reason='Something went wrong.')
