from hyprfire_app.analysis import pcapconverter, packetdata_converter
from hyprfire_app.utils.validation import arguments_valid
import logging

logger = logging.getLogger(__name__)


def ScriptProcessor(file_name, algorithm_type, window_size, analysis):
    """
     ScriptProcessor
     Uses the new scripts that were derived from Stefan's old Script. Uses memory based handling instead of reading
     and creating new files

     Parameters
     filename: the base pcap file (found in the hyprfire/pcaps directory)
     algorithm_type: whether to use benfords or zipf algorithm
     windowsize: the window size of the pcap analysis done in NewBasics3.py script

     Returns
     HTML/JavaScript to display a plotly generated graph based on the data from the pcap
     """

    # Checks if arguments being passed through is valid
    if arguments_valid(algorithm_type, window_size, analysis):

        logger.info("Starting Script Processor")
        dumpfile = pcapconverter.pcapConverter(file_name)

        if algorithm_type == 'Benford':

            algorithm = 'b'

        elif algorithm_type == 'Zipf':

            algorithm = 'z'

        if analysis == 'Length':

            analysis_type = 'l'

        elif analysis == 'Time':

            analysis_type = 't'

        csv_data = packetdata_converter.convert_to_csv(dumpfile, algorithm, int(window_size), analysis_type)

        logger.info("Script Processor is Done!")

        return csv_data

    else:
        logging.error("Value Error was raised - Possible incorrect algorithm or analysis inputted")
        raise ValueError("Error in Processing Arguments: filenames, algorithm, windowsize or analysis type")
