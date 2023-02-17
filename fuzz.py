import subprocess
import random
import string
import sys
import time
import json
import os


def gen_random(size):
    characters = string.ascii_letters + string.digits + string.punctuation
    return "".join(random.choices(characters, k=size))


def move_cursor(row, col):
    sys.stdout.write(f"\033[{row};{col}H")
    sys.stdout.flush()


def clear_line(row):
    sys.stdout.write(f"\033[{row};0H\033[K")
    sys.stdout.flush()


def format_time(seconds):
    days = seconds // (24 * 3600)
    hours = (seconds % (24 * 3600)) // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    return f"{int(days)} days, {int(hours)} hrs, {int(minutes)} min, {int(seconds)} sec"


def print_dashboard(
    start_time,
    cycles_done,
    total_paths,
    last_new_path_time,
    exec_speed,
    stage_execs,
    num_tests,
    stage_count,
    vulnerabilities_found,
):
    elapsed_time = time.time() - start_time
    red_text = "\033[91m"
    reset_text = "\033[0m"
    dashboard_lines = [
        f"                        Fuzzer Program",
        "┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐",
        f"│       run time : {format_time(elapsed_time):<36}│  cycles done : {cycles_done:<7}│",
        f"│  last new path : {format_time(time.time() - last_new_path_time):<36}│  total paths : {total_paths:<7}│",
        "├─ stage progress ────────────────────┬─ findings in depth ────────────────────┤",
        f"│ stage execs : {stage_execs:<4}/{num_tests // stage_count:<4} (stage {cycles_done + 1})   │  new edges on : 0                      │",
        f"│ total execs : {cycles_done * (num_tests // stage_count) + stage_execs:<6}                │ {red_text}total crashes : {vulnerabilities_found:<22}{reset_text} │",
        f"│  exec speed : {exec_speed:.2f}/sec (slow!){' ':<6}│ favored paths : 39 (47.56%)            │",
        "├─ path geometry ───────┬─────────────┴───── fuzzing strategy yields ──────────┤",
        f"│    levels : 0         │",
        f"│   pending : 0         │",
        "│  pend fav : 0         │",
        "│  own finds : 0        │",
        "│   imported : 0        │",
        "└───────────────────────┘",
    ]

    for i, line in enumerate(dashboard_lines):
        move_cursor(i + 1, 0)
        sys.stdout.write(line)
        sys.stdout.flush()


def fuzzer(executable_path, num_tests):
    vulnerabilities_found = 0
    found_inputs = set()
    vuln_log_path = "./vuln-log"

    if not os.path.exists(vuln_log_path):
        os.makedirs(vuln_log_path)

    start_time = time.time()
    last_new_path_time = start_time
    last_uniq_crash_time = start_time
    last_uniq_hang_time = start_time
    cycles_done = 0
    total_paths = 0
    uniq_crashes = 0
    uniq_hangs = 0
    total_execs = 0
    exec_speed = 0.0
    stage_execs = 0
    stage_count = 5

    try:
        while cycles_done * (num_tests // stage_count) + stage_execs < num_tests:
            input_size = random.randint(1, 200)
            fuzz_input = gen_random(input_size).encode()

            if fuzz_input in found_inputs:
                continue

            process = subprocess.Popen(
                [executable_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            try:
                stdout, stderr = process.communicate(input=fuzz_input, timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()

            if (
                process.returncode != 0
                or b"Overflow detected!" in stdout
                or b"Overflow detected!" in stderr
            ):
                vulnerabilities_found += 1
                found_inputs.add(fuzz_input)

                vuln_info = {
                    "input_size": input_size,
                    "fuzz_input": fuzz_input.hex(),
                    "stdout": stdout.hex(),
                    "stderr": stderr.hex(),
                }
                with open(
                    os.path.join(vuln_log_path, f"vuln_{vulnerabilities_found}.json"),
                    "w",
                ) as log_file:
                    json.dump(vuln_info, log_file, indent=4)

            total_execs += 1
            stage_execs += 1

            current_time = time.time()

            if current_time - last_new_path_time >= 86400:
                last_new_path_time = current_time
            if current_time - last_uniq_crash_time >= 86400:
                last_uniq_crash_time = current_time
            if current_time - last_uniq_hang_time >= 86400:
                last_uniq_hang_time = current_time

            if stage_execs >= num_tests // stage_count:
                stage_execs = 0
                cycles_done += 1

            exec_speed = total_execs / (current_time - start_time)
            print_dashboard(
                start_time,
                cycles_done,
                total_paths,
                last_new_path_time,
                last_uniq_crash_time,
                last_uniq_hang_time,
                uniq_crashes,
                uniq_hangs,
                exec_speed,
                stage_execs,
                num_tests,
                stage_count,
                vulnerabilities_found,
            )
            time.sleep(0.1)  # Adjust sleep interval as needed

    except KeyboardInterrupt:
        print("Fuzzing interrupted by user.")
    except Exception as e:
        print(f"Error occurred: {e}")

    print("Fuzzing complete.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <path_to_executable> <number_of_tests>")
        sys.exit(1)

    executable_path = sys.argv[1]
    num_tests = int(sys.argv[2])

    fuzzer(executable_path, num_tests)
