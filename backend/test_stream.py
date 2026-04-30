import asyncio
import json
import httpx
import websockets
from app.db.database import AsyncSessionLocal
from app.db import crud

async def main():
    async with httpx.AsyncClient(base_url="http://127.0.0.1:8000") as client:
        # 1. Get initial stats
        print("Fetching initial stats...")
        r_init = await client.get("/api/dashboard/stats", headers={"Authorization": "Bearer TEST"})
        init_stats = r_init.json() if r_init.status_code == 200 else {}
        init_threats = init_stats.get("total_threats", 0)
        init_logs = init_stats.get("total_logs_analyzed", 0)
        print(f"Initial: Threats={init_threats}, Logs={init_logs}")

        # 2. Connect to WebSocket and stream apache_access.log
        print("Connecting to stream...")
        uri = "ws://127.0.0.1:8000/api/logs/simulate/apache_access.log"
        stream_complete_payload = None
        
        try:
            async with websockets.connect(uri) as ws:
                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=20.0)
                        data = json.loads(msg)
                        if data.get("type") == "stream_complete":
                            stream_complete_payload = data.get("payload")
                            print("Stream complete received:", stream_complete_payload)
                            break
                    except asyncio.TimeoutError:
                        print("Timeout waiting for stream_complete")
                        break
        except Exception as e:
            print("WS error:", e)

        await asyncio.sleep(1) # wait for db flush
        
        # 3. Get final stats
        print("Fetching final stats...")
        r_final = await client.get("/api/dashboard/stats", headers={"Authorization": "Bearer TEST"})
        final_stats = r_final.json() if r_final.status_code == 200 else {}
        final_threats = final_stats.get("total_threats", 0)
        final_logs = final_stats.get("total_logs_analyzed", 0)
        print(f"Final: Threats={final_threats}, Logs={final_logs}")

        # Assertions
        if stream_complete_payload:
            threats_found = stream_complete_payload.get("threats_found", 0)
            lines = stream_complete_payload.get("total_lines", 0)
            print(f"Expected diff: Threats +{threats_found}, Logs +{lines}")
            print(f"Actual diff: Threats +{final_threats - init_threats}, Logs +{final_logs - init_logs}")
            
            if final_threats > init_threats or threats_found == 0:
                print("✅ TEST PASSED: Threats updated correctly")
            else:
                print("❌ TEST FAILED: Threats did not increase")
                
            if final_logs > init_logs or lines == 0:
                print("✅ TEST PASSED: Logs updated correctly")
            else:
                print("❌ TEST FAILED: Logs did not increase")
        else:
            print("❌ TEST FAILED: No stream_complete payload received")

if __name__ == "__main__":
    asyncio.run(main())
