#!/usr/bin/python3
import jinja2
import subprocess
import csv
import sys
import os
import boto3
import re
from datetime import datetime
from botocore.exceptions import ClientError
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from email.utils import COMMASPACE

# Replace this with a valid email.
SENDER = "Fuzzing service <email@example.com>"
# Replace this with the desired region.
AWS_REGION = "eu-central-1"
RECIPIENTS_FILE = ".mailinglist"
SUBJECT = "Fuzzing report"
CHARSET = "utf-8"

FUZZ_OUT_DIR_REL = 'fuzz/out'
AFL_STATS_DIR_REL = 'fuzzer01'
AFL_STATS_FILE = 'fuzzer_stats'
KCOV_COVERAGE_DIR_REL = 'kcov-report'
KCOV_COVERAGE_FILE = 'index.js'

TARGET_REGEX = r'cargo_target\/(.+)\/(debug|release)\/(\w+)_fuzz_target'
CORES_REGEX = r'fuzzer\d{2}'
KCOV_INSTRUMENTED_LINES_REGEX = r'"instrumented" : (\d+)'
KCOV_COVERED_LINES_REGEX = r'"covered" : (\d+)'

FIRECRACKER_VERSION_CMD = ['git', 'describe', '--abbrev=0']
FIRECRACKER_HASH_COMMIT_CMD = ['git', 'rev-parse', '--verify', 'HEAD', '--short']
RUSTC_VERSION_CMD = ['tools/devtool', 'devctr_exec', 'rustc --version']
AFL_VERSION_CMD = ['tools/devtool', 'devctr_exec', 'cargo afl --version']
HOST_INFO_CMD = ['uname', '-smrpio']

def get_fuzzer_stats(fuzz_out_dir):
    d = {}
    fuzzer_stats_file = os.path.join(fuzz_out_dir, AFL_STATS_DIR_REL, AFL_STATS_FILE)

    with open(fuzzer_stats_file, 'r') as file:
        fuzz_stats = {}
        lines = file.readlines()

        for line in lines:
            components = line.split(':')
            key = components[0].strip()
            value = components[1].strip()
            fuzz_stats[key] = value

        words = re.findall(TARGET_REGEX, fuzz_stats['command_line'])[0]

        d['fuzz_target'] = words[2]
        d['profile'] = words[1]
        d['target'] = words[0]
        d['cores'] = len(list((filter(re.compile(CORES_REGEX).match, os.listdir(fuzz_out_dir)))))
        d['start_time'] = datetime.fromtimestamp(int(fuzz_stats['start_time']))
        d['execs_done'] = int(fuzz_stats['execs_done'])
        d['cycles_done'] = int(fuzz_stats['cycles_done'])
        d['stability'] = fuzz_stats['stability']
        d['unique_hangs'] = int(fuzz_stats['unique_hangs'])
        d['unique_crashes'] = int(fuzz_stats['unique_crashes'])

    return d

def get_coverage(fuzz_out_dir):
    d = {}
    coverage_file = os.path.join(fuzz_out_dir, KCOV_COVERAGE_DIR_REL, KCOV_COVERAGE_FILE)

    with open(coverage_file) as cov_output:
        contents = cov_output.read()
        instrumented_linex = int(re.findall(KCOV_INSTRUMENTED_LINES_REGEX, contents)[0])
        covered_lines = int(re.findall(KCOV_COVERED_LINES_REGEX, contents)[0])

        coverage = covered_lines / instrumented_linex * 100

        d['coverage'] = '{0:0.2f}%'.format(coverage)

    return d

def get_firecracker_version(task_dir):
    return str(subprocess.check_output(FIRECRACKER_VERSION_CMD, cwd = task_dir).strip(), CHARSET)

def get_firecracker_commit(task_dir):
    return str(subprocess.check_output(FIRECRACKER_HASH_COMMIT_CMD, cwd = task_dir).strip(), CHARSET)

def get_rustc_version(task_dir):
    return str(subprocess.check_output(RUSTC_VERSION_CMD, cwd = task_dir).strip(), CHARSET)

def get_afl_version(task_dir):
    return str(subprocess.check_output(AFL_VERSION_CMD, cwd = task_dir).strip(), CHARSET)

def get_host_info():
    return str(subprocess.check_output(HOST_INFO_CMD).strip(), CHARSET)

def send_mail(html_body, text_body, attachments):
    # Create a new SES resource and specify a region.
    client = boto3.client('ses', region_name = AWS_REGION)

    recipients = []
    with open(RECIPIENTS_FILE, 'r') as file:
        recipients = file.readlines()
        recipients = list(map(lambda s: s.strip(), recipients))

    # Create a multipart/mixed parent container.
    msg = MIMEMultipart('mixed')
    # Add subject, from and to lines.
    msg['Subject'] = SUBJECT 
    msg['From'] = SENDER 

    # Create a multipart/alternative child container.
    msg_body = MIMEMultipart('alternative')

    # Encode the text and HTML content and set the character encoding.
    textpart = MIMEText(text_body.encode(CHARSET), 'plain', CHARSET)
    htmlpart = MIMEText(html_body.encode(CHARSET), 'html', CHARSET)

    # Add the text and HTML parts to the child container.
    msg_body.attach(textpart)
    msg_body.attach(htmlpart)

    msg.attach(msg_body)

    for path in attachments:
        att = MIMEApplication(open(path, 'rb').read())
        att.add_header('Content-Disposition','attachment', filename = os.path.basename(path))
        msg.attach(att)

    try:
        response = client.send_raw_email(
            Source = SENDER,
            Destinations = recipients,
            RawMessage = {
                'Data':msg.as_string(),
            },
        )
    except ClientError as e:
        print(e.response['Error']['Message'])
    else:
        print("Email sent! Message ID:"),
        print(response['MessageId'])

def main(argv):
    template_loader = jinja2.FileSystemLoader(searchpath = "./")
    template_env = jinja2.Environment(loader = template_loader)
    TEXT_TEMPLATE_FILE = "template.txt"
    HTML_TEMPLATE_FILE = "template.html"

    task_dir = str(argv[0])

    report = {'firecracker_version': get_firecracker_version(task_dir),
            'firecracker_hash': get_firecracker_commit(task_dir),
            'rustc_version': get_rustc_version(task_dir),
            'afl_version': get_afl_version(task_dir),
            'host_info': get_host_info(),
            'path': task_dir,
    }

    fuzz_out_dir = os.path.join(task_dir, FUZZ_OUT_DIR_REL)

    report.update(get_fuzzer_stats(fuzz_out_dir))
    report.update(get_coverage(fuzz_out_dir))

    text_body = template_env.get_template(TEXT_TEMPLATE_FILE).render(report = report)
    html_body = template_env.get_template(HTML_TEMPLATE_FILE).render(report = report)

    if len(argv) > 1:
        attachments = argv[1:]
    else:
        attachments = []

    send_mail(html_body, text_body, attachments)

if __name__ == '__main__':
    main(sys.argv[1:])
