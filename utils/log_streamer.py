import time

def stream_logs(file_path):
    with open(file_path, "r") as file:
        file.seek(0, 2)  # go to end of file

        while True:
            line = file.readline()

            if not line:
                time.sleep(1)
                continue

            yield line.strip()