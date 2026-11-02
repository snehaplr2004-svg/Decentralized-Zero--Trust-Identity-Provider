import requests

token = input("Paste your admin token: ").strip()

response = requests.get(
    "http://127.0.0.1:8000/admin",
    headers={"Authorization": f"Bearer {token}"}
)

print("Status code:", response.status_code)

if response.status_code == 200:
    with open("admin_dashboard.html", "w", encoding="utf-8") as file:
        file.write(response.text)

    print("Dashboard saved successfully!")
else:
    print(response.text)