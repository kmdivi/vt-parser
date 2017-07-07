#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Virustotal parser
# Query the Compilation timestamp to https://www.virustotal.com/ by sha256 value and write to csv file.

import csv
import time
import urllib.request

URL = "https://www.virustotal.com/ja/file/"
SHA256_list = "sha256_list.txt"
OUTPUT_FILE = "result.csv"


def send_http_request(url, sha256):
    """
    Send http request.
    Return html src as http response.
    """
    print(url + sha256 + '/analysis/')
    try:
        req = urllib.request.Request(url + sha256 + '/analysis/')
        with urllib.request.urlopen(req) as response:
            html = response.read()
    except:
        html = None
    return html


def extract_value_from_html(html):
    """
    Extract file informations from html src.
    Return the list of file informations.
    """
    file_info = []
    try:
        filename = html.split("ファイル名:")[1].split('<td>')[1].split('</td>')[0]
        sha256 = html.split("SHA256:")[1].split('<td>')[1].split('</td>')[0]
        # detection_rate = html.split("検出率:")[1].split('text-red ">')[1].split('</td>')[0]
        # analysis_date = html.split("分析日時:")[1].split('<td>')[1].split('UTC')[3]
        compilation_time = html.split("Compilation")[1].split('</span>')[1].split('</div>')[0]

        filename = filename.strip()
        sha256 = sha256.strip()
        compilation_time = compilation_time.strip()

        file_info.append(filename)
        file_info.append(sha256)
        # file_info.append(detection_rate)
        # file_info.append(analysis_date)
        file_info.append(compilation_time)
        return file_info
    except:
        return "N/A"


def byte2str(byte_html):
    str_html = byte_html.decode('utf-8')
    return str_html


def export_to_csv(file_info):
    table_headline = ['Filename', 'SHA256', 'Compilation timestamp']
    with open(OUTPUT_FILE, 'a') as f:
        writecsv = csv.writer(f, lineterminator="\n")
        writecsv.writerow(table_headline)
        for i in (range(len(file_info))):
            writecsv = csv.writer(f, lineterminator="\n")
            writecsv.writerow(file_info[i])


def main():
    file_info = []
    with open(SHA256_list, 'r') as f:
        sha256_list = f.readlines()
    for sha256 in sha256_list:
        print('Now processing ' + str(sha256_list.index(sha256) + 1) + '/' + str(len(sha256_list)) + '...')

        tmp = []
        sha256 = sha256.rstrip('\n')
        html = send_http_request(URL, sha256)
        if html is not None:
            str_html = byte2str(html)
            tmp = extract_value_from_html(str_html)
            time.sleep(30)
            file_info.append(tmp)
    export_to_csv(file_info)
    print('FINISHED!!!')


if __name__ == '__main__':
    main()
