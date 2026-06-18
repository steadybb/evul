import sys
import runpy
from pathlib import Path


def run():
    failures = 0
    tests_path = Path(__file__).parent
    test_files = sorted(tests_path.glob('test_*.py'))
    if not test_files:
        print('No test files found')
        sys.exit(2)

    for test_file in test_files:
        print(f"Running {test_file.name}")
        ns = runpy.run_path(str(test_file))
        tests = [v for k, v in ns.items() if callable(v) and k.startswith('test_')]
        for func in tests:
            name = f'{test_file.name}::{func.__name__}'
            try:
                func()
                print(f'PASS: {name}')
            except AssertionError as e:
                print(f'FAIL: {name} - {e}')
                failures += 1
            except Exception as e:
                print(f'ERROR: {name} - {e}')
                failures += 1

    if failures:
        print(f"{failures} failure(s)")
        sys.exit(1)
    print('All tests passed')


if __name__ == '__main__':
    run()
