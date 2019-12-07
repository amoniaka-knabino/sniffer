import argparse


def get_parsed_args():
    parser = argparse.ArgumentParser(description="sniff your traffic <3")
    parser.add_argument('-f', '--file', dest='filename',
                        help="output pcap filename. default: temp.pcap")
    parser.add_argument('-c', '--console', dest='console_mode',
                        action='store_true',
                        help="console print mode (without pcap)")
    parser.add_argument('--network_proto',
                        dest='network_proto', help="TODO")
    parser.add_argument('--trasport_proto',
                        dest='trasport_proto', help="TODO")
    parser.add_argument('--ip', dest='ip', help="TODO")
    parser.add_argument('--port', dest='port', help="TODO")
    return parser.parse_args()
