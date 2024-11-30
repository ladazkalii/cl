import socket
import hashlib
import json

def connect_to_pool(pool_address, pool_port):
    """Menghubungkan ke pool mining."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((pool_address, pool_port))
        print(f"Terhubung ke pool: {pool_address}:{pool_port}")
        return sock
    except Exception as e:
        print(f"Gagal terhubung ke pool: {e}")
        return None

def send_request(sock, request):
    """Mengirimkan permintaan JSON ke pool."""
    try:
        sock.sendall(json.dumps(request).encode('utf-8') + b'\n')
    except Exception as e:
        print(f"Gagal mengirimkan permintaan: {e}")

def receive_response(sock):
    """Menerima respons JSON dari pool."""
    try:
        response = sock.recv(1024).decode('utf-8')
        return json.loads(response)
    except Exception as e:
        print(f"Gagal menerima respons: {e}")
        return None

def mine_xelisv2_pepew(data, target):
    """Menambang menggunakan algoritma xelisv2-pepew."""
    nonce = 0
    while True:
        block_data = f"{data}{nonce}".encode('utf-8')
        hash_result = hashlib.sha256(block_data).hexdigest()
        if int(hash_result, 16) < int(target, 16):
            return nonce, hash_result
        nonce += 1

def main():
    # Ganti dengan alamat pool dan port zpool
    pool_address = "stratum+tcp://minotaurx.na.mine.zpool.ca"
    pool_port = 7019  # Ganti dengan port algoritma spesifik
    
    # Masukkan alamat dompet dan password Anda
    wallet_address = "RHMpzNMhM3vhwLy8eiEG1hGtm1oUefA3fM"
    password = "c=RVN"  # Ganti sesuai koin yang Anda tambang

    # Menghubungkan ke pool
    sock = connect_to_pool(pool_address, pool_port)
    if not sock:
        return

    # Login ke pool
    login_request = {
        "id": 1,
        "method": "mining.subscribe",
        "params": []
    }
    send_request(sock, login_request)

    # Terima respons login
    response = receive_response(sock)
    if response and "result" in response:
        print("Berhasil login ke pool.")
    else:
        print("Gagal login ke pool.")
        return

    # Kirim detail wallet dan password
    authorize_request = {
        "id": 2,
        "method": "mining.authorize",
        "params": [wallet_address, password]
    }
    send_request(sock, authorize_request)

    # Loop untuk menerima dan memproses pekerjaan
    while True:
        job = receive_response(sock)
        if not job or 'method' not in job or job['method'] != 'mining.notify':
            continue
        
        job_id = job['params'][0]
        prev_hash = job['params'][1]
        coinb1 = job['params'][2]
        coinb2 = job['params'][3]
        merkle_branch = job['params'][4]
        version = job['params'][5]
        nbits = job['params'][6]
        ntime = job['params'][7]
        clean_jobs = job['params'][8]

        print(f"Job diterima: {job_id}")

        # Mulai proses mining
        nonce, result = mine_xelisv2_pepew(prev_hash, nbits)

        # Kirim hasil ke pool
        submit_request = {
            "id": 4,
            "method": "mining.submit",
            "params": [wallet_address, job_id, nonce, ntime, result]
        }
        send_request(sock, submit_request)

        # Tunggu respons dari pool
        response = receive_response(sock)
        if response and response.get('result', False):
            print("Share diterima!")
        else:
            print("Share ditolak.")

if _name_ == "_main_":
    main()
