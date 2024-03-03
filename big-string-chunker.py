"""
This tool is used for chunk a big string into pieces of 80 characters
"""
from argparse import ArgumentParser
import sys

def unchunk_string(chunked_string):
    new_string = chunked_string.replace('"', '')
    new_string = new_string.replace("\n", '')
    new_string = new_string.replace("  ", '')
    return new_string


def chunk_string(big_string, chunk_size=80):
    formatted_string = ""
    chunks = [big_string[i:i+chunk_size] for i in range(0, len(big_string), chunk_size)]
    for i, chunk in enumerate(chunks):
        if i == len(chunks) - 1:
            formatted_string += f'"{chunk}"\n'
        else:
            formatted_string += f'"{chunk}"\n  '
        # formatted_string += f'"{chunk}"\n  '
    return f"1: {{\n  {formatted_string}}}"


def get_content_from_stdin():
    return sys.stdin.buffer.read().decode()


def get_content_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            return file.read()

    except Exception as e:
        print('Error Occurred in Reading Input File: ' + str(e))
        exit(1)


def print_parser_help(prog):
    help_msg = f"""echo payload | python3 {prog} --stdin [--chunk OR --un-chunk]
    Arguments:
      --chunk       chunk a big string into pieces of 80 chars
      --un-chunk    un-chunk the chunked data (remove ['"','\\n','  '])
    Input Arguments:
      --stdin       get input from standard input
      --file        get input from a file
    Help:
      --help        print help message
    
    Examples:
      echo payload | python3 {prog} --stdin
      python3 {prog} --file big_string.txt
"""

    print(help_msg)


if __name__ == '__main__':
    parser = ArgumentParser(usage='echo payload | python3 %(prog)s --stdin',
                            allow_abbrev=False, add_help=False)

    parser.add_argument('--help', action='store_true', default=False)
    parser.add_argument('--chunk', action='store_true', default=False)
    parser.add_argument('--un-chunk', action='store_true', default=False)
    parser.add_argument('--stdin', action='store_true', default=False)
    parser.add_argument('--file', default=None)

    args, unknown = parser.parse_known_args()

    if (args.stdin is not True) and (args.file is None):
        print_parser_help(parser.prog)
        print('--stdin or --file is not set!')
        exit(1)

    if (args.chunk is not True) and (args.un_chunk is not True):
        print_parser_help(parser.prog)
        print('--chunk or --un-chunk is not set!')
        exit(1)

    if args.file is None:
        content = get_content_from_stdin()
    else:
        content = get_content_from_file(file_path=args.file)

    if args.chunk:
        result = chunk_string(content.strip())
    else:
        result = unchunk_string(content)
    print(result)
