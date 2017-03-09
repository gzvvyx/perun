"""Raw printing of the profiles, i.e. without any formatting.

Raw printing is the simplest printing of the given profiles, i.e. without any
formatting and visualization techniques at all.
"""

import termcolor

from perun.utils.helpers import RAW_ATTRS, RAW_ITEM_COLOUR, RAW_KEY_COLOUR

__author__ = 'Tomas Fiedor'


def process_object(item, colour, coloured):
    """
    Arguments:
        item(str): item we are processing by the show
        colour(str): colour used to colour the object
        coloured(bool): whether the item should be coloured or not

    Returns:
        str: coloured or uncoloured item
    """
    if coloured:
        return termcolor.colored(item, colour, attrs=RAW_ATTRS)
    else:
        return item


def show(profile, coloured=False):
    """
    Arguments:
        profile(dict): dictionary profile
        coloured(bool): true if the output should be in colours

    Returns:
        str: string representation of the profile
    """
    RAW_INDENT = 4

    # Construct the header
    header = profile['header']
    for header_item in ['type', 'cmd', 'params', 'workload']:
        if header_item in header.keys():
            print("{}: {}".format(
                process_object(header_item, RAW_KEY_COLOUR, coloured),
                process_object(header[header_item], RAW_ITEM_COLOUR, coloured)
            ))

    print('')

    # Construct the collector info
    if 'collector' in profile.keys():
        print(process_object('collector:', RAW_KEY_COLOUR, coloured))
        collector_info = profile['collector']
        for collector_item in ['name', 'params']:
            if collector_item in collector_info.keys():
                print(RAW_INDENT*1*' ' + "- {}: {}".format(
                    process_object(collector_item, RAW_KEY_COLOUR, coloured),
                    process_object(
                        collector_info[collector_item] or 'none', RAW_ITEM_COLOUR, coloured
                    )
                ))


def show_coloured(profile):
    """
    Arguments:
        profile(dict): dictionary profile

    Returns:
        str: string representation of the profile with colours
    """
    show(profile, True)