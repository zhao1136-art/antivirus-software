import urllib.request
import uuid

boundary = "----WebKitFormBoundary" + uuid.uuid4().hex
eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
body = b""
body += ("--" + boundary + "\r\n").encode()
body += b'Content-Disposition: form-data; name="file"; filename="eicar_test.txt"\r\n'
body += b"Content-Type: text/plain\r\n\r\n"
body += eicar + b"\r\n"
body += ("--" + boundary + "--\r\n").encode()
req = urllib.request.Request(
    "http://47.93.118.106/api/scan",
    data=body,
    headers={"Content-Type": "multipart/form-data; boundary=" + boundary},
)
print(urllib.request.urlopen(req, timeout=30).read().decode()[:4000])
