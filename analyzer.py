from collections import defaultdict
import floss.strings
from stringsifter.rank_strings import *
import mmap
import contextlib
import math
import os
import csv
import statistics


def count_files(directory: str):
    total = 0
    for root, dirs, files in os.walk(directory):
        total += len(files)
    return total


def files_from_directory_gen(directory: str):
    for root, dirs, files in os.walk(directory):
        for f in files:
            yield os.path.join(root, f)


def get_file_strings(file: str, min_length: int = 4):
    with open(file, "rb") as f:
        with contextlib.closing(mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)) as buf:
            yield from (i.string for i in floss.strings.extract_ascii_strings(buf, min_length))
            yield from (j.string for j in floss.strings.extract_unicode_strings(buf, min_length))


def analyze_by_percent(directory: str):
    sr = StringsRanker()
    result_dict = defaultdict(float)
    cnt = 0
    for file in files_from_directory_gen(directory):
        cnt += 1
        print(cnt, file)
        strings_ranked = sr.rank_strings(get_file_strings(file))
        scores, strings = list(zip(*strings_ranked))
        for p in range(1, 100 + 1):
            cur_index = math.ceil((len(scores) / 100.0) * p) if p != 100 else len(scores)
            result_dict[p] += sum(scores[:cur_index])
    return result_dict


def method_01(malicious_directory: str, benign_directory: str, out_csv: str):
    malicious_count = count_files(malicious_directory)
    benign_count = count_files(benign_directory)
    print("After count")
    malicious_dict = analyze_by_percent(malicious_directory)
    benign_dict = analyze_by_percent(benign_directory)
    print("After analyze")
    with open(out_csv, "w") as csv_file:
        csv_header = ["Percent", "Malicious_average", "benign_average"]
        writer = csv.writer(csv_file)
        writer.writerow(csv_header)
        for p in range(1, 100 + 1):
            writer.writerow([p, malicious_dict[p] / malicious_count, benign_dict[p] / benign_count])


def main():
    lengths = set()
    malicious_dir = r"E:\TEST FILES\viruses\executable\pe\exe"
    benign_dir = r"E:\TEST FILES\benign\pe\exe"
    for file in files_from_directory_gen(malicious_dir):
        print(file)
        for s in get_file_strings(file, min_length=5):
            lengths.add(len(s))
    lengths.add(4)

    median = statistics.median(lengths)
    avr = round(statistics.mean(lengths), 3)
    max_len = max(lengths)
    number_of_lengths = len(lengths)
    print(f"{median =}")
    print(f"{avr =}")
    print(f"{max_len =}")
    print(f"{number_of_lengths =}")


if __name__ == '__main__':
    main()
