"""
Encode and Decode GRPC-Web Base64 Encoded Payload for Pentesting GRPC-Web
"""

import base64
import binascii
import sys
from argparse import ArgumentParser


def decode_b64_payload(b64_content):
    try:
        decoded = base64.b64decode(b64_content)
    except Exception as e:
        print('Error occurred while decoding b64 payload: ' + str(e))
        exit(1)

    return decoded


def encode_b64_payload(content_input):
    base64_encoded = base64.b64encode(content_input)
    return base64_encoded.decode('utf-8')


def convert_to_hex(content):
    try:
        hex_rep = binascii.hexlify(content)
    except Exception as e:
        print('Error occurred while converting payload to hex: ' + str(e))
        exit(1)

    return hex_rep


def split_grpc_length_prefix(hex_input):
    """
    split length prefix and payload from hex input
    :param hex_input:
    :return: length_prefix, payload
    """
    hex_input = hex_input.decode()
    length_prefix = hex_input[0:10]
    payload = hex_input[10:]

    return length_prefix, payload


def calculate_length_from_length_prefix(length_prefix):
    try:
        tmp = int(length_prefix, 16) * 2  # * 2 is bcs each byte has 2 characters
    except Exception as e:
        print('Error occurred while calculating length of payload: ' + str(e))
        exit(1)

    return tmp


def read_payload_based_on_length(payload, length):
    temp_str = payload[0:length]
    return temp_str


def convert_payload_hex_to_formatted_output(hex_payload):
    # convert for example 0a0d02 to \\x0a\\x0d\\x02

    temp_str = ""
    for i in range(0, len(hex_payload)):

        if i % 2 == 0:
            temp_str += r"\\x" + hex_payload[i]
        else:
            temp_str += hex_payload[i]

    return temp_str


def convert_hex_to_ascii(hex_input):
    return bytes.fromhex(hex_input)


def convert_ascii_to_b64(ascii_input):
    encoded_b64 = base64.b64encode(ascii_input)
    return encoded_b64.decode('utf-8')


def get_padded_length_of_new_payload(payload):
    length = len(payload) / 2
    length = int(length)
    tmp = format(length, 'x')

    if len(tmp) < 10:
        tmp = "0" * (10 - len(tmp)) + tmp

    return tmp


def decoder(content_input):
    """
    application/grpc-web-text decoder
    :param content_input:
    :return:
    """

    base64_decoded = decode_b64_payload(content_input)
    b64_to_hex = convert_to_hex(base64_decoded)
    payload_length_prefix, payload = split_grpc_length_prefix(b64_to_hex)
    length = calculate_length_from_length_prefix(payload_length_prefix)
    main_payload = read_payload_based_on_length(payload, length)
    # formatted_output = convert_payload_hex_to_formatted_output(main_payload)
    ascii_payload = convert_hex_to_ascii(main_payload)

    sys.stdout.buffer.write(ascii_payload)


def encoder(content_input):
    """
    application/grpc-web-text encoder
    :param content_input:
    :return:
    """

    hex_converted = convert_to_hex(content_input)
    hex_length_prefix = get_padded_length_of_new_payload(hex_converted)
    new_payload_with_length_prefix = hex_length_prefix + str(hex_converted.decode())
    ascii_result = convert_hex_to_ascii(new_payload_with_length_prefix)
    b64_result = convert_ascii_to_b64(ascii_result)
    print(b64_result)


def grpc_web_encoder(content_input):
    """
    application/grpc-web+proto encoder
    :param content_input:
    :return:
    """

    hex_converted = convert_to_hex(content_input)
    hex_length_prefix = get_padded_length_of_new_payload(hex_converted)
    new_payload_with_length_prefix = hex_length_prefix + str(hex_converted.decode())
    ascii_payload = convert_hex_to_ascii(new_payload_with_length_prefix)

    sys.stdout.buffer.write(ascii_payload)


def grpc_web_decoder(content_input):
    """
    application/grpc-web-text decoder
    :param content_input:
    :return:
    """

    base64_encoded_content = encode_b64_payload(content_input)
    decoder(base64_encoded_content)


def print_parser_help(prog):
    help_msg = f"""echo payload | python3 {prog} [--encode OR --decode]

    General Arguments:
      --encode       encode protoscope binary output to application/grpc-web-text
      --decode       decode application/grpc-web-text base64 encoded payload to protoscope format
      --type         content-type of payload [default: grpc-web-text] available types: [grpc-web-text, grpc-web+proto]
    
    Input Arguments:
    Default Input is Standard Input
      --file        to get input from a file 
    
    Help:
      --help        print help message
"""

    print(help_msg)


def get_content_from_stdin():
    return sys.stdin.buffer.read()


def get_content_from_file(file_path):
    try:
        with open(file_path, 'rb') as file:
            return file.read()

    except Exception as e:
        print('Error Occurred in Reading Input File: ' + str(e))
        exit(1)


if __name__ == '__main__':
    parser = ArgumentParser(usage='echo payload | python3 %(prog)s [--encode or --decode]',
                            allow_abbrev=False, add_help=False)

    parser.add_argument('--help', action='store_true', default=False)
    parser.add_argument('--encode', action='store_true')
    parser.add_argument('--decode', action='store_true')
    parser.add_argument('--file', default=None)
    parser.add_argument('--type', default='grpc-web-text')

    args, unknown = parser.parse_known_args()

    if (args.encode is not True) and (args.decode is not True):
        print_parser_help(parser.prog)
        exit(1)

    if args.file is None:
        content = get_content_from_stdin()
    else:
        content = get_content_from_file(file_path=args.file)
    if args.decode is True:
        if args.type == 'grpc-web-text':
            decoder(content)
        elif args.type == 'grpc-web+proto':
            grpc_web_decoder(content)
        else:
            print('Invalid Content-Type: ' + args.type)
            print('Available types: grpc-web-text OR grpc-web+proto')
    else:
        if args.type == 'grpc-web-text':
            encoder(content)
        elif args.type == 'grpc-web+proto':
            grpc_web_encoder(content)
        else:
            print('Invalid Content-Type: ' + args.type)
            print('Available types: grpc-web-text OR grpc-web+proto')
