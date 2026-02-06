import os
import time
from typing import Dict, Any, Optional

import numpy as np
import pydicom
import timm
import torch
from PIL import Image
from pydicom.pixel_data_handlers.util import apply_voi_lut
from torchvision import transforms


class Predictor:
    def __init__(
        self,
        weights_path: str,
        arch: str = "tf_efficientnet_b4_ns",
        img_size: int = 380,
        device: Optional[str] = None,
    ):
        if device is None:
            device = "cuda" if torch.cuda.is_available() else "cpu"
        self.device = torch.device(device)

        self.model = timm.create_model(arch, pretrained=False, num_classes=1).to(self.device).eval()

        state = torch.load(weights_path, map_location=self.device)
        if isinstance(state, dict) and "state_dict" in state:
            state = state["state_dict"]

        if isinstance(state, dict):
            state = {k.replace("module.", ""): v for k, v in state.items()}

        missing, unexpected = self.model.load_state_dict(state, strict=True)
        if missing or unexpected:
            raise RuntimeError(f"State_dict mismatch. missing={len(missing)} unexpected={len(unexpected)}")

        self.tf = transforms.Compose([
            transforms.Resize((img_size, img_size)),
            transforms.ToTensor(),
            transforms.Normalize([0.485, 0.456, 0.406],
                                 [0.229, 0.224, 0.225]),
        ])

    @torch.no_grad()
    def predict(self, path: str) -> Dict[str, Any]:
        t0 = time.perf_counter()

        img = self._load_as_pil_rgb(path)
        x = self.tf(img).unsqueeze(0).to(self.device)

        y = self.model(x)  # logits shape: (1,1)
        logit = y.float().view(-1)[0]
        prob = torch.sigmoid(logit).item()

        latency_ms = int((time.perf_counter() - t0) * 1000)
        label = "PNEUMONIA" if prob >= 0.5 else "NORMAL"

        return {
            "prob": float(prob),
            "label": label,
            "threshold": 0.5,
            "latency_ms": latency_ms,
        }

    def _load_as_pil_rgb(self, path: str) -> Image.Image:
        ext = os.path.splitext(path)[1].lower()
        if ext in (".jpg", ".jpeg", ".png", ".bmp", ".webp"):
            return Image.open(path).convert("RGB")
        # otherwise treat as DICOM
        return self._dicom_to_pil_rgb(path)

    def _dicom_to_pil_rgb(self, path: str) -> Image.Image:
        ds = pydicom.dcmread(path, force=True)
        arr = ds.pixel_array.astype(np.float32)

        try:
            arr = apply_voi_lut(arr, ds).astype(np.float32)
        except Exception:
            pass

        slope = float(getattr(ds, "RescaleSlope", 1.0))
        intercept = float(getattr(ds, "RescaleIntercept", 0.0))
        arr = arr * slope + intercept

        if str(getattr(ds, "PhotometricInterpretation", "")).upper() == "MONOCHROME1":
            arr = arr.max() - arr

        lo, hi = np.percentile(arr, 1), np.percentile(arr, 99)
        arr = np.clip(arr, lo, hi)
        arr = (arr - lo) / (hi - lo + 1e-6)
        img8 = (arr * 255.0).astype(np.uint8)

        return Image.fromarray(img8, mode="L").convert("RGB")

