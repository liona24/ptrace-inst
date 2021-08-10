import libwrap

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("args", nargs="+")

    args = parser.parse_args()

    proc = libwrap.Process()

    proc.start_process(args.args[0], args.args, [])

    while True:
        proc.run_continue()
