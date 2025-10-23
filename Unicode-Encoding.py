#!/usr/bin/env python3
import argparse

def selectively_unicode_escape(payload, times=1):
    # Only convert special chars <, >, = to unicode escape sequences repeatedly
    for _ in range(times):
        new_payload = []
        for c in payload:
            if c == '<':
                new_payload.append('\\u003C')
            elif c == '>':
                new_payload.append('\\u003E')
            elif c == '=':
                new_payload.append('\\u003D')
            else:
                new_payload.append(c)
        payload = ''.join(new_payload)
    return payload

def process_payloads(input_file, output_file, encode_times):
    try:
        with open(input_file, 'r') as f:
            payloads = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"Error reading payloads file: {e}")
        return

    try:
        with open(output_file, 'w') as f_out:
            for p in payloads:
                encoded = selectively_unicode_escape(p, encode_times)
                f_out.write(encoded + '\n')
        print(f"Processed {len(payloads)} payloads with encoding layers: {encode_times} and saved to {output_file}")
    except Exception as e:
        print(f"Error writing output file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Convert only <, >, = in payloads to Unicode escapes with multiple layers")
    parser.add_argument('-p', '--payloads', required=True, help='Input payloads file')
    parser.add_argument('-o', '--output', required=True, help='Output file for encoded payloads')
    parser.add_argument('-e', '--encode-times', type=int, choices=[1,2,3], default=1, help='Encoding layers (default 1)')

    args = parser.parse_args()
    process_payloads(args.payloads, args.output, args.encode_times)

if __name__ == "__main__":
    main()

