"""Owned loopback-only CI sink. Counts fixed synthetic frames, never replies."""
import socket
import threading

TARGET = ('198.18.0.9', 38555)
PAYLOAD = b'liwetun-synthetic-tx-only-261117'


class TxOnlySink:
    def __init__(self, port=38555):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(('127.0.0.1', port))
        self.socket.listen(2)
        self.socket.settimeout(.2)
        self.address = self.socket.getsockname()
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts = dict(accepted=0, received_bytes=0, matched_frames=0,
                           rejected_frames=0, sent_bytes=0)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def count(self, key, value=1):
        with self.lock:
            self.counts[key] += value

    def stats(self):
        with self.lock:
            return dict(self.counts)

    def serve(self):
        while not self.stop.is_set():
            try:
                client, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.count('accepted')
            with client:
                client.settimeout(.2)
                pending = b''
                received = 0
                while not self.stop.is_set() and received < 65536:
                    try:
                        chunk = client.recv(4096)
                        if not chunk:
                            break
                        received += len(chunk)
                        self.count('received_bytes', len(chunk))
                        pending += chunk
                        while len(pending) >= len(PAYLOAD):
                            frame, pending = pending[:len(PAYLOAD)], pending[len(PAYLOAD):]
                            if frame != PAYLOAD:
                                self.count('rejected_frames')
                                return
                            self.count('matched_frames')
                    except socket.timeout:
                        continue
                    except OSError:
                        break

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)
