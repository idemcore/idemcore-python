# Agent tái lập được: ghi, phát lại, xác minh

Một lần chạy agent là một chuỗi lời gọi mô hình và lời gọi công cụ (tool). Idemcore
đã ký một biên nhận (receipt) cho mỗi câu trả lời của mô hình. **Trace** nối các biên
nhận đó với các lời gọi tool của bạn thành một chuỗi băm, để sau này bạn chứng minh
được agent đã thấy gì, làm gì, và chạy lại để nhận đúng các câu trả lời đó, khớp
từng token.

| | Chức năng | Mạng |
|---|---|---|
| `Session` / `record()` | Ghi lời gọi mô hình (kèm biên nhận) và lời gọi tool vào một trace có chuỗi băm | Chỉ các lời gọi API bạn vốn đã gọi |
| `verify_trace()` | Kiểm tra chuỗi, mọi giá trị băm, chữ ký và cam kết của từng biên nhận, và chữ ký của bạn | **không cần** |
| `replay()` | Gửi lại các yêu cầu mô hình đã ghi, kiểm tra token đầu ra giống hệt từng bit, và trả kết quả tool đã ghi cho agent | một lời gọi API cho mỗi bước mô hình |

## Ghi

```python
import idemcore
from idemcore import trace

client = idemcore.Idemcore()          # lấy IDEMCORE_API_KEY từ biến môi trường

def get_weather(city):
    return {"city": city, "temp_c": 18}

def agent(s):
    city = s.chat("Which city is the Eiffel Tower in? One word.", max_tokens=8).text.strip(" .")
    w = s.tool("get_weather", {"city": city}, get_weather)       # chạy tool, ghi tham số + kết quả
    return s.chat(f"Weather: {w}. One-sentence forecast.", max_tokens=40).text

s = trace.Session(client, meta={"job": "forecast-demo"})
agent(s)
s.save("run.trace.json")
```

* `s.chat(...)` nhận đúng các tham số như `client.chat(...)`.
* `s.tool(name, args, fn)` gọi `fn(**args)` (hoặc `fn(args)` nếu `args` không phải dict). Ngoại lệ được ghi lại rồi ném tiếp.
* `s.record_tool(name, args, result)` ghi một tool bạn tự chạy (ví dụ lời gọi hàm mà mô hình yêu cầu).
* `s.record_model(result, max_tokens=...)` ghi một câu trả lời dạng stream: `s.record_model(client.chat_stream(...).until_done(), ...)`.
* `s.note("approval", {...})` thêm một bước tự do, ví dụ người duyệt ký xác nhận.
* Tham số và kết quả tool phải là JSON (số, chuỗi, mảng, đối tượng). Tham số được lưu dạng JSON chuẩn tắc (khoá sắp xếp); kết quả giữ nguyên thứ tự khoá mà tool trả về, để agent khi phát lại nhận đúng y hệt đối tượng đó.

### Ký trace

```python
key = trace.generate_signing_key()     # JWK bí mật; cất giữ như mọi khoá bí mật
s.save("run.trace.json", sign_with=key)
print(key["kid"])                       # công bố id này để người khác ghim (pin)
```

Trace chỉ lưu khoá công khai và chữ ký, không bao giờ lưu phần bí mật.

## Xác minh (offline)

```bash
python -m idemcore trace verify run.trace.json --signer ed25519:1a2b3c4d5e6f7a8b
python -m idemcore trace show run.trace.json
```

```python
res = trace.verify_trace(trace.load_trace("run.trace.json"), trusted_signers=["ed25519:..."])
assert res.ok, res.errors
```

`verify_trace` báo lỗi nếu có bước nào bị sửa, xoá, chèn hoặc đổi thứ tự, nếu
manifest bị thay đổi, nếu chữ ký biên nhận không đến từ khoá Idemcore tin cậy, hoặc
nếu prompt, token đầu ra hay văn bản đã ghi không khớp cam kết trong biên nhận.
Không cần mạng. Truyền `keys=` để dùng bộ khoá lấy từ `GET /v1/keys` thay cho bộ
khoá kèm theo SDK.

## Phát lại (replay)

```bash
python -m idemcore trace replay run.trace.json          # chỉ các lời gọi mô hình
```

```python
report = trace.replay(trace.load_trace("run.trace.json"), client, agent=agent)
print(report.summary())     # OK: 2/2 model steps bit-identical, 1 tool/note steps fed from the trace
```

* **Chỉ mô hình** (không có `agent=`): gửi lại từng yêu cầu đã ghi theo thứ tự; id token, văn bản, chain digest, số token, mô hình và weights hash phải khớp.
* **Phát lại agent** (`agent=fn`): mã agent của bạn chạy lại với một `ReplaySession`. Lời gọi mô hình đi tới API và được kiểm tra. Lời gọi tool trả về kết quả đã ghi và **không chạy tool**, nên phát lại an toàn cả với tool có tác dụng phụ (thanh toán, gửi email, ghi dữ liệu) và cho cùng đầu vào dù thế giới bên ngoài đã thay đổi. Nếu agent gọi khác đi (khác thứ tự hoặc khác tham số), replay dừng và báo vị trí.
* `strict=True` dừng ngay ở câu trả lời khác đầu tiên.
* Thay đổi `engine_build` chỉ được ghi chú, không tính là lỗi: câu trả lời vẫn phải giống hệt từng bit.
* `report.replay_trace` là trace mới của chính lần phát lại (trong `meta_json` có id phiên gốc), nên lần phát lại cũng kiểm toán được.

## Trace chứng minh được gì, và không chứng minh được gì

* Chứng minh mỗi câu trả lời mô hình do Idemcore tạo ra cho đúng yêu cầu đó (biên nhận có chữ ký), và chuỗi bước không bị sửa kể từ lúc ghi (chuỗi băm, chữ ký tuỳ chọn).
* Kết quả tool là những gì **mã của bạn** đã ghi. Trace cho thấy chúng không bị sửa sau đó, nhưng không chứng minh được tool đã thật sự trả về chúng. Nếu điều đó quan trọng, hãy ký trace ngay tại nguồn và giữ log riêng của tool.
* Trace chứa prompt, câu trả lời và salt dùng để mở biên nhận `hash_only`. Hãy lưu trữ nó cẩn thận như chính cuộc hội thoại.

## Định dạng trace (`idemcore-trace/r1`)

Định dạng và các công thức băm giống hệt bản tiếng Anh: xem mục "Trace format" trong
[agent-replay.md](agent-replay.md). Tóm tắt: mỗi bước có `index`, `type`
(`model` | `tool` | `note`), `prev` (băm bước trước), `body` và `hash`; manifest cam
kết `session_id`, số bước và `head` (băm bước cuối); chữ ký Ed25519 ký trên
`"idemcore-trace/r1\n" ‖ manifest_hash`. Trace ghi bằng Python xác minh được bằng
JavaScript và ngược lại.
