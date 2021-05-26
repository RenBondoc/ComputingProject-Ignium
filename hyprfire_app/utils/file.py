from pathlib import Path
from hyprfire.settings import BASE_DIR
from pathvalidate import sanitize_filename

PCAPS_DIR = Path(BASE_DIR) / 'pcaps'


def get_filename_list():
    """
    get_filename_list

    Helper function to retrieve a list of non-hidden filenames from the pcaps directory

    Return
    A list of non-hidden filenames in the pcaps directory
    """
    filenames = []

    for file in PCAPS_DIR.glob('*'):
        name = file.stem.lower()
        if file.is_file() and not name.startswith('.'):
            filenames.append(name)

    return filenames


def get_file(filename):
    """
    get_file

    Function that will check the user inputted "filename" if a file of that name exists in the pcaps
    directory.

    If a file does exist, return the filepath of that file.

    :param filename: user inputted filename
    :return: file path of the proper file
    """
    split_array = filename.split(';')
    new_file = Path(split_array[0]).stem
    sanitized_name = sanitize_filename(new_file)
    for items in PCAPS_DIR.glob('*'):
        if items.stem.lower() == sanitized_name.lower():
            return str(items.stem) + str(items.suffix)

    raise FileNotFoundError("File Cannot be Found")
