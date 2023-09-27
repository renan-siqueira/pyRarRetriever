import subprocess
import os
import itertools
import threading
import queue
import time
import signal

import settings


PAUSE_REQUESTED = False
PASSWORD_FOUND = threading.Event()

NUM_THREADS = settings.NUM_THREADS


def signal_handler(signum, frame):
    global PAUSE_REQUESTED
    PAUSE_REQUESTED = True

signal.signal(signal.SIGINT, signal_handler)


def save_progress(base_password, last_attempted_password):
    with open(settings.PATH_PROGRESS_FILE, 'w') as f:
        f.write(f"{base_password}\n{last_attempted_password}")


def format_time(elapsed_time):
    if elapsed_time < 60:
        return f"{elapsed_time:.2f} seconds"
    elif elapsed_time < 3600:
        return f"{elapsed_time / 60:.2f} minutes"
    else:
        return f"{elapsed_time / 3600:.2f} hours"


def extract_rar(rar_filename, password, output_dir):
    cmd = ['unrar', 'x', '-p' + password, rar_filename, output_dir]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if "Incorrect password" not in result.stderr:
        PASSWORD_FOUND.set()
        return True
    else:
        return False


def generate_case_combinations(password):
    return [''.join(p) for p in itertools.product(*[(c.lower(), c.upper()) for c in password])]


def worker(rar_filename, task_queue, lock):
    while not task_queue.empty() and not PASSWORD_FOUND.is_set():
        try:
            base_password, combinations = task_queue.get_nowait()

            start_time = time.time()
            for passwd in combinations:
                if PAUSE_REQUESTED or PASSWORD_FOUND.is_set():
                    save_progress(base_password, passwd)
                    return

                with lock:
                    print(f"Trying password: {passwd}")

                if extract_rar(rar_filename, passwd):
                    with lock:
                        print(f"Password found and files extracted: {passwd}")
                    return

            end_time = time.time()
            elapsed_time = end_time - start_time

            with lock:
                with open(settings.PATH_LOG_FILE, 'a') as log_file:
                    formatted_time = format_time(elapsed_time)
                    log_file.write(f"Password: {base_password}, Time taken: {formatted_time}\n")

        except queue.Empty:
            return


def main():
    rar_filename = settings.PATH_RAR_FILE

    if not os.path.exists(settings.PATH_EXTRACTED_FOLDER):
        os.mkdir(settings.PATH_EXTRACTED_FOLDER)

    task_queue = queue.Queue()

    start_from = None
    last_attempted = None
    if os.path.exists(settings.PATH_PROGRESS_FILE):
        with open(settings.PATH_PROGRESS_FILE, 'r') as f:
            lines = f.readlines()
            if len(lines) == 2:
                start_from = lines[0].strip()
                last_attempted = lines[1].strip()

    start_processing = False
    with open(settings.PATH_BASE_FILE, 'r') as file:
        for base_password in file:
            base_password = base_password.strip()

            if start_from and base_password == start_from:
                start_processing = True

            if start_processing:
                combinations = generate_case_combinations(base_password)
                if last_attempted:
                    combinations = combinations[combinations.index(last_attempted) + 1:]
                    last_attempted = None
                task_queue.put((base_password, combinations))

    print_lock = threading.Lock()
    open(settings.PATH_LOG_FILE, 'a').close()

    threads = []
    for _ in range(NUM_THREADS):
        t = threading.Thread(target=worker, args=(rar_filename, task_queue, print_lock))
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    if not PASSWORD_FOUND.is_set():
        print("Brute-force completed without finding the password.")
    else:
        print("Password found!")

    print(f"Check the {settings.PATH_LOG_FILE} file for the logged times.")


if __name__ == '__main__':
    main()
