import argparse


def get_parsed_args():
    parser = argparse.ArgumentParser(description="sniff your traffic <3")
    parser.add_argument('-i', '--interface',
                        help='name of interface to capture traffic',
                        default='', dest='interface')
    parser.add_argument('-f', '--file', dest='filename',
                        help="output pcap filename (tmpfile by default)")
    parser.add_argument('-c', '--console', dest='console_mode',
                        action='store_true',
                        help="console print mode (without pcap)")
    parser.add_argument('-d', '--debug',
                        help='mode with printing exception details',
                        action='store_true',
                        dest='debug')
    parser.add_argument('--filter',
                        help=("filter expression (look sniffer.py -l). "
                              "now is only for console mode"),
                        dest='filter_exr', default='')
    parser.add_argument('-l', '--filter-list', action='store_true',
                        dest='show_filter_list',
                        help="list of possible filters and istruction")
    return parser.parse_args()
