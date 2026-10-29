def test_root_endpoint(client):
    res = client.get("/")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "online"

def test_system_status(client):
    res = client.get("/api/v1/system/status")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["backend_available"] is True
    assert "version" in data
    assert "active_interface" in data

def test_system_interfaces(client):
    res = client.get("/api/v1/system/interfaces")
    assert res.status_code == 200
    ifaces = res.json()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    names = [i["name"] for i in ifaces]
    assert "Synthetic Mode" in names

def test_system_settings(client):
    res = client.get("/api/v1/system/settings")
    assert res.status_code == 200
    data = res.json()
    assert "interface" in data
    assert "packet_capture_enabled" in data

    res_put = client.put("/api/v1/system/settings", json={"interface": "Synthetic Mode", "dark_mode": True})
    assert res_put.status_code == 200
    assert res_put.json()["interface"] == "Synthetic Mode"
