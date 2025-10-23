#!/usr/bin/env python3
import argparse
import re

def insert_null_bytes_all_blocks(payload):
    # Insert %00 in all alphabetical blocks after 2nd letter if length >=3 else after 1st
    def replace_block(match):
        block = match.group(0)
        length = len(block)
        if length >= 3:
            # Insert %00 after 2nd letter
            return block[:2] + '%00' + block[2:]
        elif length >= 1:
            # Insert %00 after 1st letter (to cover all blocks)
            return block[0] + '%00' + block[1:]
        else:
            return block
    return re.sub(r'[a-zA-Z]+', replace_block, payload)

def process_payloads(input_file, output_file):
    try:
        with open(input_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading payloads file: {e}")
        return

    try:
        with open(output_file, 'w') as fout:
            for p in payloads:
                encoded = insert_null_bytes_all_blocks(p)
                fout.write(encoded + '\n')
        print(f"Processed {len(payloads)} payloads inserting null bytes for all blocks, saved to {output_file}")
    except Exception as e:
        print(f"Error writing to output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Insert %00 null byte after letters in all alphabetical blocks for WAF bypass")
    parser.add_argument('-p', '--payloads', required=True, help="Input payload file")
    parser.add_argument('-o', '--output', required=True, help="Output file")

    args = parser.parse_args()
    process_payloads(args.payloads, args.output)

if __name__ == "__main__":
    main()
