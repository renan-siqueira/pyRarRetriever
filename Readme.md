# pyRarRetriever

---

## Description

pyRarRetriever is a Python-based tool crafted to retrieve passwords from password-protected RAR files. By leveraging brute-force techniques, the tool attempts password combinations to unpack the RAR file, aiding in the recovery of forgotten passwords.

---

## Project Flow

1. The program reads a base password list from a text file.

2. For each base password, the program generates combinations of uppercase and lowercase characters.

3. Using multiple threads, it attempts to unpack the RAR file using each password combination.

4. If a correct password is found, the program unpacks the file and terminates.

5. If the program is interrupted, it saves its progress and can be resumed later.

---

## Setup and Usage

### 1. Clone the Repository:

```bash
git clone https://github.com/renan-siqueira/pyRarRetriever.git
cd pyRarRetriever
```

### 2. Set Up a Virtual Environment:

```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows use: venv\Scripts\activate
```

### 3. Install Required Packages:

```bash
pip install -r requirements.txt
```

### 4. Configuration:

Create or Modify the `settings.py` file with the necessary settings:

- `NUM_THREADS`: Number of threads to use.
- `PATH_RAR_FILE`: Path to the RAR file you want to extract.
- `PATH_BASE_FILE`: Path to the file containing the base passwords.
- `PATH_EXTRACTED_FOLDER`: Folder where the files will be extracted upon successful decryption.
- `PATH_PROGRESS_FILE`: File where the progress will be saved in case of interruption.
- `PATH_LOG_FILE`: File where the logs for each password attempt will be saved.

### 5. Run the Program:

```bash
python main.py
```

*If you wish to pause the process, simply interrupt it (e.g., by pressing Ctrl+C). When you restart, it will resume from where it left off.*
