###############################################################################
# fuzz.py                                                                     #
# Author: Gavin Faircloth (glf0016@auburn.edu)                                #
# Date: 12/1/25                                                               #
# Description: This fuzzer tests key Python methods in the MLForensics project#
# we were given for a class project.                                          #
###############################################################################

import sys
import os
import traceback
import random
import string
import tempfile
import shutil
from datetime import datetime, timedelta
import ast

# Add paths to import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'FAME-ML'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'mining'))

# Import modules to test
try:
    import py_parser
    import lint_engine
    import mining
except ImportError as e:
    print(f"Error importing modules: {e}")
    sys.exit(1)

###############################################################################
#                REPORT GENERATOR CLASS                                       #
###############################################################################

# Reports fuzzing results and discovered bugs
class FuzzReporter:
    
    # Setting variables
    def __init__(self):
        self.bugs_found = []
        self.test_count = 0
        self.crash_count = 0
        
    # Log individual test results
    def log_test(self, method_name, input_data, result, error=None):
        self.test_count += 1
        if error:
            self.crash_count += 1
            bug_info = {
                'method': method_name,
                'input': str(input_data)[:100],  # Truncate long inputs
                'error_type': type(error).__name__,
                'error_msg': str(error),
                'traceback': traceback.format_exc()
            }
            self.bugs_found.append(bug_info)
        
    # Make final report
    def generate_report(self):
        print("\n" + "="*80)
        print("FUZZING REPORT")
        print("="*80)
        print(f"Total tests executed: {self.test_count}")
        print(f"Bugs/Crashes found: {self.crash_count}")
        print(f"Success rate: {((self.test_count - self.crash_count) / self.test_count * 100):.2f}%")
        print("="*80)
        
        if self.bugs_found:
            print("\nDETAILED BUG REPORTS:")
            print("-"*80)
            for i, bug in enumerate(self.bugs_found, 1):
                print(f"\nBUG #{i}")
                print(f"Method: {bug['method']}")
                print(f"Input: {bug['input']}")
                print(f"Error Type: {bug['error_type']}")
                print(f"Error Message: {bug['error_msg']}")
                print(f"Traceback:\n{bug['traceback']}")
                print("-"*80)
        else:
            print("\n✓ No bugs found! All tests passed successfully.")
            
        # Write report to file
        with open('fuzz_report.txt', 'w') as f:
            f.write("="*80 + "\n")
            f.write("FUZZING REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total tests executed: {self.test_count}\n")
            f.write(f"Bugs/Crashes found: {self.crash_count}\n")
            f.write(f"Success rate: {((self.test_count - self.crash_count) / self.test_count * 100):.2f}%\n")
            f.write("="*80 + "\n\n")
            
            if self.bugs_found:
                f.write("DETAILED BUG REPORTS:\n")
                f.write("-"*80 + "\n")
                for i, bug in enumerate(self.bugs_found, 1):
                    f.write(f"\nBUG #{i}\n")
                    f.write(f"Method: {bug['method']}\n")
                    f.write(f"Input: {bug['input']}\n")
                    f.write(f"Error Type: {bug['error_type']}\n")
                    f.write(f"Error Message: {bug['error_msg']}\n")
                    f.write(f"Traceback:\n{bug['traceback']}\n")
                    f.write("-"*80 + "\n")
            else:
                f.write("\n✓ No bugs found! All tests passed successfully.\n")
        
        print(f"\n✓ Full report saved to: fuzz_report.txt")


class Fuzzer:
    """Main fuzzer class"""
    
    def __init__(self):
        self.reporter = FuzzReporter()
        
###############################################################################
#                      RANDOM INPUT GENERATORS                                #
###############################################################################

    def generate_random_string(self, length=None):
        """Generate random string"""
        if length is None:
            length = random.randint(0, 100)
        return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))
    
    def generate_random_python_code(self):
        """Generate random Python-like code for testing parsers"""
        templates = [
            "import random\nprint('hello')",
            "def func():\n    pass",
            "class Test:\n    def __init__(self):\n        pass",
            "x = 1 + 2",
            "",  # Empty string
            "invalid python code @#$%",
            "def func(\n    incomplete",
            "'''multiline\nstring\n'''",
            "\n\n\n",  # Just newlines
            self.generate_random_string(),
            "# " + self.generate_random_string(),
            "import " + self.generate_random_string(),
        ]
        return random.choice(templates)
    
    def create_temp_python_file(self, content):
        """Create a temporary Python file"""
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
        temp_file.write(content)
        temp_file.close()
        return temp_file.name
    
    def generate_random_date(self):
        """Generate random datetime object"""
        base = datetime(2020, 1, 1)
        random_days = random.randint(-1000, 1000)
        return base + timedelta(days=random_days)
    
###############################################################################
#                      FUZZING METHODS                                        #
###############################################################################

#################### Method 1: Fuzz getPythonParseObject() ####################
    def fuzz_getPythonParseObject(self, iterations=20):
        print(f"\n[1/5] Fuzzing py_parser.getPythonParseObject() with {iterations} iterations...")
        
        for i in range(iterations):
            # Generate random Python code
            code = self.generate_random_python_code()
            temp_file = self.create_temp_python_file(code)
            
            try:
                result = py_parser.getPythonParseObject(temp_file)
                self.reporter.log_test('getPythonParseObject', f"file: {temp_file}, content: {code[:50]}", result)
            except Exception as e:
                self.reporter.log_test('getPythonParseObject', f"file: {temp_file}, content: {code[:50]}", None, e)
            finally:
                # Cleanup
                try:
                    os.unlink(temp_file)
                except:
                    pass
        
        # Test with non-existent files
        for i in range(5):
            fake_file = '/nonexistent/' + self.generate_random_string() + '.py'
            try:
                result = py_parser.getPythonParseObject(fake_file)
                self.reporter.log_test('getPythonParseObject', f"file: {fake_file}", result)
            except Exception as e:
                self.reporter.log_test('getPythonParseObject', f"file: {fake_file}", None, e)
    
#################### Method 2: Fuzz checkLoggingPerData() ####################
    def fuzz_checkLoggingPerData(self, iterations=20):
        print(f"\n[2/5] Fuzzing py_parser.checkLoggingPerData() with {iterations} iterations...")
        
        for i in range(iterations):
            # Generate random Python code with various patterns
            code_templates = [
                "import logging\nlogging.getLogger('test')",
                "logger.info(test_data)",
                "import tensorflow as tf\ntf.logging.info('message')",
                self.generate_random_python_code(),
                "",
                "# no logging here",
            ]
            code = random.choice(code_templates)
            temp_file = self.create_temp_python_file(code)
            
            try:
                tree = py_parser.getPythonParseObject(temp_file)
                name_to_track = random.choice([
                    'data',
                    'test_var',
                    self.generate_random_string(10),
                    '',
                    None,
                    123,  # Invalid type
                ])
                result = py_parser.checkLoggingPerData(tree, name_to_track)
                self.reporter.log_test('checkLoggingPerData', f"name: {name_to_track}, code: {code[:50]}", result)
            except Exception as e:
                self.reporter.log_test('checkLoggingPerData', f"name: {name_to_track}, code: {code[:50]}", None, e)
            finally:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    
#################### Method 3: Fuzz days_between() ####################
    def fuzz_days_between(self, iterations=20):
        print(f"\n[3/5] Fuzzing mining.days_between() with {iterations} iterations...")
        
        for i in range(iterations):
            # Generate random datetime objects
            try:
                d1 = self.generate_random_date()
                d2 = self.generate_random_date()
                result = mining.days_between(d1, d2)
                self.reporter.log_test('days_between', f"d1: {d1}, d2: {d2}", result)
            except Exception as e:
                self.reporter.log_test('days_between', f"d1: {d1}, d2: {d2}", None, e)
        
        # Test edge cases and invalid inputs
        edge_cases = [
            (None, None),
            (datetime.now(), None),
            (None, datetime.now()),
            ("2020-01-01", "2021-01-01"),  # Strings instead of datetime
            (123, 456),  # Numbers
            ([], {}),  # Invalid types
            (datetime(1900, 1, 1), datetime(2100, 12, 31)),  # Large range
            (datetime.now(), datetime.now()),  # Same dates
        ]
        
        for d1, d2 in edge_cases:
            try:
                result = mining.days_between(d1, d2)
                self.reporter.log_test('days_between', f"d1: {d1}, d2: {d2}", result)
            except Exception as e:
                self.reporter.log_test('days_between', f"d1: {d1}, d2: {d2}", None, e)
    
#################### Method 4: Fuzz getPythonFileCount() ####################
    def fuzz_getPythonFileCount(self, iterations=20):
        print(f"\n[4/5] Fuzzing mining.getPythonFileCount() with {iterations} iterations...")
        
        # Create temp directories with Python files
        for i in range(iterations):
            temp_dir = tempfile.mkdtemp()
            
            try:
                # Create random number of Python files
                num_py_files = random.randint(0, 10)
                for j in range(num_py_files):
                    py_file = os.path.join(temp_dir, f"test{j}.py")
                    with open(py_file, 'w') as f:
                        f.write(self.generate_random_python_code())
                
                # Create some non-Python files
                num_other_files = random.randint(0, 5)
                for j in range(num_other_files):
                    ext = random.choice(['.txt', '.md', '.json', '.yml'])
                    other_file = os.path.join(temp_dir, f"file{j}{ext}")
                    with open(other_file, 'w') as f:
                        f.write(self.generate_random_string())
                
                # Create some .ipynb files (should also be counted)
                num_ipynb = random.randint(0, 3)
                for j in range(num_ipynb):
                    ipynb_file = os.path.join(temp_dir, f"notebook{j}.ipynb")
                    with open(ipynb_file, 'w') as f:
                        f.write('{"cells": []}')
                
                result = mining.getPythonFileCount(temp_dir)
                expected = num_py_files + num_ipynb
                self.reporter.log_test('getPythonFileCount', 
                    f"dir: {temp_dir}, py_files: {num_py_files}, ipynb: {num_ipynb}, expected: {expected}, got: {result}", 
                    result)
            except Exception as e:
                self.reporter.log_test('getPythonFileCount', f"dir: {temp_dir}", None, e)
            finally:
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
        
        # Test with non-existent and invalid directories
        invalid_dirs = [
            '/nonexistent/directory',
            '',
            None,
            self.generate_random_string(),
            '../../../etc',  # Path traversal attempt
            '/dev/null',  # Not a directory
        ]
        
        for dir_path in invalid_dirs:
            try:
                result = mining.getPythonFileCount(dir_path)
                self.reporter.log_test('getPythonFileCount', f"dir: {dir_path}", result)
            except Exception as e:
                self.reporter.log_test('getPythonFileCount', f"dir: {dir_path}", None, e)
    
#################### Method 5: Fuzz getDataLoadCount() ####################
    def fuzz_getDataLoadCount(self, iterations=20):
        print(f"\n[5/5] Fuzzing lint_engine.getDataLoadCount() with {iterations} iterations...")
        
        for i in range(iterations):
            # Generate Python code with various data loading patterns
            code_templates = [
                "import torch\ntorch.load('file.pth')",
                "import pickle\npickle.load(open('file.pkl', 'rb'))",
                "import json\njson.load(open('file.json'))",
                "import pandas as pd\npd.read_csv('data.csv')",
                "from PIL import Image\nImage.open('image.jpg')",
                self.generate_random_python_code(),
                "",
                "# no data loading here",
                "import numpy as np\nnp.load('data.npy')",
            ]
            code = random.choice(code_templates)
            temp_file = self.create_temp_python_file(code)
            
            try:
                result = lint_engine.getDataLoadCount(temp_file)
                self.reporter.log_test('getDataLoadCount', f"file: {temp_file}, code: {code[:50]}", result)
            except Exception as e:
                self.reporter.log_test('getDataLoadCount', f"file: {temp_file}, code: {code[:50]}", None, e)
            finally:
                try:
                    os.unlink(temp_file)
                except:
                    pass
        
        # Test with non-existent files
        for i in range(5):
            fake_file = '/nonexistent/' + self.generate_random_string() + '.py'
            try:
                result = lint_engine.getDataLoadCount(fake_file)
                self.reporter.log_test('getDataLoadCount', f"file: {fake_file}", result)
            except Exception as e:
                self.reporter.log_test('getDataLoadCount', f"file: {fake_file}", None, e)
    
    def run_all_fuzzing(self, iterations=20):
        """Run all fuzzing tests"""
        print("="*80)
        print("STARTING FUZZING TESTS")
        print("="*80)
        print(f"Running {iterations} iterations per method...")
        
        self.fuzz_getPythonParseObject(iterations)
        self.fuzz_checkLoggingPerData(iterations)
        self.fuzz_days_between(iterations)
        self.fuzz_getPythonFileCount(iterations)
        self.fuzz_getDataLoadCount(iterations)
        
        print("\n" + "="*80)
        print("FUZZING COMPLETE")
        print("="*80)
        
        self.reporter.generate_report()


def main():
    print("""
    =========================================================================
    |           Fuzzer for MLForensics                                      |
    |           (COMP6710 Project)                                          |
    =========================================================================
    """)
    
    # Allow custom iteration count from command line
    iterations = 20
    if len(sys.argv) > 1:
        try:
            iterations = int(sys.argv[1])
            print(f"Using custom iteration count: {iterations}")
        except ValueError:
            print("Invalid iteration count, using default: 20")
    
    fuzzer = Fuzzer()
    fuzzer.run_all_fuzzing(iterations)
    
    print("\n✓ Fuzzing session completed successfully!")
    print("Check 'fuzz_report.txt' for detailed results.")
    
    # Exit with appropriate status code
    if fuzzer.reporter.crash_count > 0:
        print(f"\n⚠ WARNING: {fuzzer.reporter.crash_count} bugs/crashes detected!")
        sys.exit(1)  # Non-zero exit code indicates failures
    else:
        print("\n✓ All tests passed - no bugs detected!")
        sys.exit(0)  # Zero exit code indicates success


if __name__ == '__main__':
    main()
