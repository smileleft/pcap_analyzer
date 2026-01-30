import uvicorn
import subprocess
import json
import os
from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

# CORS 설정 (React 연동)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

@app.post("/upload")
async def upload_pcap(file: UploadFile = File(...)):
    file_path = os.path.join(UPLOAD_DIR, file.filename)
    with open(file_path, "wb") as f:
        f.write(await file.read())
    return {"filename": file.filename, "status": "uploaded"}

@app.get("/packets")
async def get_packets(filename: str, page: int = 1, limit: int = 50):
    file_path = os.path.join(UPLOAD_DIR, filename)
    start_pos = (page - 1) * limit

    # tshark를 사용하여 메타데이터만 추출 (Pagination 적용)
    # -T fields를 사용하면 JSON보다 훨씬 빠르게 필요한 컬럼만 추출 가능
    cmd = [
        "tshark", "-r", file_path,
        "-T", "fields",
        "-e", "frame.number", "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport", "-e", "tcp.stream", "-e", "frame.len",
        "-Y", "tcp",
        "-c", str(limit),
        "-o", f"gui.column.format:\"No.\",\"%m\"" # 특정 지점부터 읽기 위해 추가 로직 필요
    ]

    # 실제 구현 시 -Y "frame.number > start_pos" 필터를 추가하여 페이징 최적화
    result = subprocess.run(cmd, capture_output=True, text=True)

    lines = result.stdout.strip().split('\n')
    packets = []
    for line in lines:
        fields = line.split('\t')
        if len(fields) >= 7:
            packets.append({
                "id": fields[0], "src": fields[1], "dst": fields[2],
                "sport": fields[3], "dport": fields[4], "stream_id": fields[5], "len": fields[6]
            })

    return {"packets": packets}

@app.get("/stream/{stream_id}")
async def follow_stream(filename: str, stream_id: int):
    file_path = os.path.join(UPLOAD_DIR, filename)

    # tshark의 stream follow 기능 활용 (TCP 세션 재조합)
    cmd = ["tshark", "-r", file_path, "-z", f"follow,tcp,ascii,{stream_id}"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    return {"content": result.stdout}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8888)
