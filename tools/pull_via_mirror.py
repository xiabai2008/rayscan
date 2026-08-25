"""从 DaoCloud 镜像源手动下载 Docker 镜像并 docker load（绕过 Clash 代理大连接 EOF）。

用法: python pull_via_mirror.py iisimpler/landray-oa:1.0
"""
import base64
import hashlib
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

MIRROR = "https://docker.m.daocloud.io"
AUTH = "https://m.daocloud.io/auth/token"


def http_get(url, headers=None, timeout=120):
    req = urllib.request.Request(url, headers=headers or {})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(req, timeout=timeout) as r:
        return r.read()


def get_token(repo):
    url = f"{AUTH}?service=docker.m.daocloud.io&scope=repository:{repo}:pull"
    data = json.loads(http_get(url))
    return data["token"]


def main():
    ref = sys.argv[1]
    repo, tag = ref.split(":", 1) if ":" in ref else (ref, "latest")
    token = get_token(repo)
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json",
    }
    print(f"[1/4] fetch manifest {repo}:{tag}")
    manifest = json.loads(http_get(f"{MIRROR}/v2/{repo}/manifests/{tag}", headers))
    layers = manifest.get("layers", [])
    config_digest = manifest.get("config", {}).get("digest", "")
    print(f"      layers={len(layers)} config={config_digest[:20]}...")

    workdir = tempfile.mkdtemp(prefix="imgpull_")
    layer_dirs = []
    for i, layer in enumerate(layers):
        digest = layer["digest"]
        media = layer["mediaType"]
        fname = os.path.join(workdir, f"layer_{i}.tar.gz")
        print(f"[2/4] layer {i+1}/{len(layers)} {digest[:20]}... ({layer.get('size',0)//1024}KB)")
        blob = http_get(f"{MIRROR}/v2/{repo}/blobs/{digest}", headers)
        with open(fname, "wb") as f:
            f.write(blob)
        # 校验 sha256
        assert hashlib.sha256(blob).hexdigest() == digest.split(":")[1], f"sha256 mismatch {digest}"
        # 解压 layer 到独立目录（docker load 需要 layer.tar）
        ldir = os.path.join(workdir, f"layer_{i}")
        os.makedirs(ldir)
        with tarfile.open(fname, "r:gz") as tf:
            tf.extractall(ldir)
        # 生成 docker 需要的 VERSION / json 文件
        with open(os.path.join(ldir, "VERSION"), "w") as f:
            f.write("1.0")
        with open(os.path.join(ldir, "json"), "w") as f:
            json.dump({"id": digest.split(":")[1], "architecture": manifest.get("architecture", "amd64")}, f)
        layer_dirs.append(ldir)

    print(f"[3/4] fetch config {config_digest[:20]}...")
    config = http_get(f"{MIRROR}/v2/{repo}/blobs/{config_digest}", headers)
    config_path = os.path.join(workdir, "config.json")
    with open(config_path, "wb") as f:
        f.write(config)
    config_id = hashlib.sha256(config).hexdigest()

    # 组装 docker save 格式 tar
    save_path = os.path.join(workdir, "image.tar")
    manifest_entry = {
        "Config": "config.json",
        "RepoTags": [ref],
        "Layers": [f"layer_{i}/layer.tar" for i in range(len(layers))],
    }
    print(f"[4/4] assemble {save_path}")
    with tarfile.open(save_path, "w") as tf:
        tf.add(config_path, arcname="config.json")
        for i, ldir in enumerate(layer_dirs):
            tf.add(os.path.join(ldir, "VERSION"), arcname=f"layer_{i}/VERSION")
            tf.add(os.path.join(ldir, "json"), arcname=f"layer_{i}/json")
            # layer.tar 是解压后的目录内容
            layer_tar_path = os.path.join(workdir, f"layer_{i}_content.tar")
            with tarfile.open(layer_tar_path, "w") as ltf:
                for root, _, files in os.walk(ldir):
                    for fn in files:
                        if fn in ("VERSION", "json"):
                            continue
                        full = os.path.join(root, fn)
                        arc = os.path.relpath(full, ldir)
                        ltf.add(full, arcname=arc)
            tf.add(layer_tar_path, arcname=f"layer_{i}/layer.tar")
        with open(os.path.join(workdir, "manifest.json"), "w") as f:
            json.dump([manifest_entry], f)
        tf.add(os.path.join(workdir, "manifest.json"), arcname="manifest.json")

    print(f"docker load < {save_path}")
    with open(save_path, "rb") as f:
        r = subprocess.run(["docker", "load"], stdin=f, capture_output=True, text=True)
    print(r.stdout)
    print(r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
