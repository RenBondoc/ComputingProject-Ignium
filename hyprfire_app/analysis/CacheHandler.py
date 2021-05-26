# This File here will handle the "anaylze request" from the Django Framework
# The file must be able to handle the configuration items that have been sent from the analyze request.

from hyprfire_app.analysis import plot_csvdata
from hyprfire_app.analysis.ScriptProcessor import ScriptProcessor
from hyprfire_app.models import Data
import logging

logger = logging.getLogger(__name__)


def CacheHandler(file_name, algorithm_type, window_size, analysis):
    """
    CacheHandler
    This function does the "caching" section of the application. It does a quick check in the database if there is an
    item that has the exact: filename, algorithm_type, windowsize and analysis.
    If it does it will then grab it from the data instead.

    Else it will run the ScriptProcessor, then save the data to the database at the end.

    :param file_name: the filepath/name of the pcap file to search for/process
    :param algorithm_type: either Benford or Zipf
    :param window_size: an integer on
    :param analysis:
    :return:
    """

    # Gets a queryset from the database on how many Data of the same filename, algorithm, windowsize and analysis
    result = Data.objects.filter(filename=file_name, algorithm=algorithm_type, window_size=window_size,
                                 analysis=analysis)

    if len(result) != 0:
        # If it is more than 0 then it exists in the database, and just pull the data from there.
        logger.info("Item already exists in the database.... pulling cached data")
        csv_data = Data.objects.get(filename=file_name, algorithm=algorithm_type, window_size=window_size,
                                    analysis=analysis)
        csv_data = csv_data.data

    else:

        csv_data = ScriptProcessor(file_name, algorithm_type, window_size, analysis)

        # Create a new Object (ORM)
        database = Data.objects.create(filename=file_name, algorithm=algorithm_type, window_size=window_size,
                                       analysis=analysis, data=csv_data)
        # Save it to the database
        database.save()

    response = plot_csvdata.get_plot(csv_data)

    return response



