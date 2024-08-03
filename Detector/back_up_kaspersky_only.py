from __future__ import print_function
import concurrent.futures, threading, json, sys, requests, sys, platform, time
import os, urllib.request, urllib.error, hashlib, logging, getpass, multiprocessing
from time import sleep
from pathlib import Path
from virus_total_apis import PublicApi as VirusTotalPublicAPI
from watchdog.events import FileSystemEvent, PatternMatchingEventHandler
from watchdog.observers import Observer
from datetime import datetime, timedelta
executor = concurrent.futures.ThreadPoolExecutor()
futures = []
stopping = threading.Event()
API_kaspersky = "KYWWPxgaQDercL9ZLk0F2A=="
no_upload = ""
max_upload_size= 10 * 1024*1024
folder_1 = "Desktop"
folder_2 = "Music"
folder_3 = "Pictures"
folder_4 = "Videos"
folder_5 = "Documents"
folder_6 = "Downloads"
log_content=""

def my_logger(name):
	#get a custom logger & set the logging level
	__name__ = name
	py_logger = logging.getLogger(__name__)
	py_logger.setLevel(logging.INFO)

	# configure the handler and formatter as needed
	py_handler = logging.FileHandler(f"{__name__}.log", mode='a')
	user = getpass.getuser()
	py_formatter = logging.Formatter('%(asctime)s -%(process)d - %(message)s' + f' userid:{user}')

	# add formatter to the handler
	py_handler.setFormatter(py_formatter)
	# add handler to the logger
	py_logger.addHandler(py_handler)

	return py_logger

report_kaspersky_logger = my_logger("kaspersky_reported")
moved_logger = my_logger("moved")
delete_logger = my_logger("deleted")

def DeleteFile(file_path):
    delete_logger.info(f"Deleted file : {file_path}")
    try:
        # print(f"Deleting file '{file_path}'")
        os.remove(file_path)
    except :
        pass
            

class Handler(PatternMatchingEventHandler):
    def __init__(self) -> None:
        PatternMatchingEventHandler.__init__(self,
                                               ignore_directories=True,
                                               case_sensitive=False)#patterns=['*.png', '*.jpg', '*.doc', '*.xls', '*.ppt', '*.docx', '*.xlsx', '*.pptx', '*.pdf', '*.dll', '*.exe', '*.temp']
        self.last_modified = datetime.now()
    def on_any_event(self, event):
        if datetime.now() - self.last_modified < timedelta(seconds=1):
            return
        else:
            if not event.src_path.endswith(".log"):
                if event.event_type == "created":
                    print("Watchdog -- received created event - % s." % event.src_path)
                    if os.path.isfile(event.src_path):
                        scan_file_kaspersky(event.src_path)
                elif event.event_type == "moved":
                    print("Watchdog -- received moved event - % s." % event.src_path)
                    moved_logger.info(f"Watchdog received moved event {event.src_path} to {event.dest_path}")
                    if os.path.isfile(event.dest_path):
                        scan_file_kaspersky(event.dest_path)
                              
def mul_process(path_folder):
	m = multiprocessing.Process(target=monitor_folder, args=(path_folder,))
	m.start()

event_handler = Handler()
observer = Observer()
def monitor_folder(path_folder):
	
	observer.schedule(event_handler, path=path_folder, recursive=True)
	observer.start()
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
		observer.join()

class OpenTIP:

    def __init__(self, APIKEY:str, no_upload=False, max_upload_size=10 * 1024*1024):
        self.APIKEY = APIKEY
        self.no_upload = no_upload
        self.max_upload_size = max_upload_size
        self.frontend_url = 'https://opentip.kaspersky.com/api/v1/'
    
    def opentip_get(self, req:str):
        url = self.frontend_url + req
        req = urllib.request.Request(url)
        req.add_header('x-api-key', self.APIKEY)
        with urllib.request.urlopen(req) as f:
            data = f.read().decode('utf8')
        return data
    def opentip_post(self, req:str, data):
        url = self.frontend_url + req
        req = urllib.request.Request(url, method='POST', data=data)
        req.add_header('x-api-key', self.APIKEY)
        req.add_header('Content-Type', 'application/octet-stream')
        with urllib.request.urlopen(req) as f:
            data = f.read().decode('utf-8')
        return data
    def get_verdict_by_ioc(self, ioc_type:str, ioc_value:str):
        try:
            return self.opentip_get('search/' + ioc_type + '?request=' + ioc_value)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            else:
                raise
    def scan_file(self, filename):
        print(f"Kaspersky -- Scanning file : {filename}")
        h = hashlib.new('sha256')
        buf = b''
        try:
            with open(filename, 'rb') as f:
                while True:
                    new_buf = f.read(self.max_upload_size)
                    if not new_buf:
                        break
                    buf = new_buf
                    h.update(buf)
        except:
            return(filename, None)
        sha = h.hexdigest()

        res = self.get_verdict_by_ioc('hash', sha)
        if res is None:
            if os.path.isfile(filename):
                file_size = os.path.getsize(filename)
                if self.no_upload or (file_size > self.max_upload_size or file_size == 0):
                    return (filename, None)
                else:
                    try:
                        res = self.opentip_post('scan/file?filename=' + sha, buf)
                        if not res:
                            raise RuntimeError(filename)
                        else:
                            return (filename, res)
                    except urllib.error.HTTPError as e:
                        raise RuntimeError(('Error uploading %s') % filename)
            else:
                return(filename, None)
        return (filename, res)
        # return res

client = OpenTIP(API_kaspersky, no_upload, max_upload_size)
    
def scan_file_with_client(filename):
    if stopping.is_set():
        return
    try:
        return client.scan_file(filename)
    except:
        stopping.set()
        raise
def scan_file_wrapper(filename):
    futures.append(executor.submit(scan_file_with_client, filename))

def write_report_file_kaspersky(data, file_path, startfile_time, file_name):
    endfile_time = time.time()
    verdict = data['FileGeneralInfo']['FileStatus']
    elapsed_file = round(endfile_time - startfile_time, 2)
    # print(f"Kaspersky -- File {file_path} has {data['FileGeneralInfo']['FileStatus']} \n")
    if verdict != 'Clean' and verdict != 'NotCategorized' and verdict != 'NoThreats':
        #report_kaspersky_logger.info(f"{file_path} has {data['FileGeneralInfo']['FileStatus']} \n")
        if 'DetectionsInfo' in data:
            if os.path.isfile(file_path):
                try:
                    print(f'Kaspersky -- Deleted : file {file_path}\n')
                    DeleteFile(file_path)
                except:
                     pass
            verdict  += ': ' + ','.join(item['DetectionName'] for item in data['DetectionsInfo'])
            # print(f"Kaspersky -- Result:\n verdict: {verdict} \n Count: {len(data['DetectionsInfo'])}")
            # print(f"Kaspersky -- Write report Kaspersky file {file_path} \n")
            report_kaspersky_logger.info(f"File has {len(data['DetectionsInfo'])} : {verdict}")
            report_kaspersky_logger.info(f"Result of {file_name} : {data['FileGeneralInfo']['FileStatus']} | {endfile_time}s | Threats : {len(data['DetectionsInfo'])} | Extension : {data['FileGeneralInfo']['Type']}")
            print(f"Result of {file_name} : {data['FileGeneralInfo']['FileStatus']} | {endfile_time}s | Threats : {len(data['DetectionsInfo'])} | Extension : {data['FileGeneralInfo']['Type']}")
    else:
         report_kaspersky_logger.info(f"{file_path} has {data['FileGeneralInfo']['FileStatus']} \n")
         print(f"Result of {file_name} : {data['FileGeneralInfo']['FileStatus']}")
def scan_file_kaspersky(folder_path):
    # ret = 0
    # folder = "Documents"
    # folder_path = str(os.path.join(Path.home(), folder))
    # print(folder_path)
    startfile_time = time.time()
    endfile_time  = 0
    scan_file_wrapper(folder_path)
    for f in concurrent.futures.as_completed(futures):
        # count = 0
        res = f.result()
        if not res is None:
            filename = res[0]
            # print(f"file name : {filename}\n")
            # loud_verdict = None
            if res[1] is None:
                print(f"Kaspersky -- File {folder_path} not have report")
            else:
                try:
                    data = json.loads(res[1])
                    write_report_file_kaspersky(data, folder_path, startfile_time, filename)
                except json.decoder.JSONDecodeError as e:
                    verdict = res[1]
                    # loud_verdict = True

def main():

    

    if platform.system() == "Windows" or platform.system() == "Linux":    

        folder1_path = str(os.path.join(Path.home(), folder_1))
        folder2_path = str(os.path.join(Path.home(), folder_2))
        folder3_path = str(os.path.join(Path.home(), folder_3))
        folder4_path = str(os.path.join(Path.home(), folder_4))
        folder5_path = str(os.path.join(Path.home(), folder_5))
        folder6_path = str(os.path.join(Path.home(), folder_6))
    else :
        exit()

  

    mul_process(folder1_path)
    mul_process(folder2_path)
    mul_process(folder3_path)
    mul_process(folder4_path)
    mul_process(folder5_path)
    mul_process(folder6_path)
if __name__=='__main__':
    try :
        multiprocessing.freeze_support()
        main()
    except :
         sys.exit(0)
