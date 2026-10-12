import {
  cancel,
  confirm,
  intro,
  isCancel,
  log,
  multiselect,
  note,
  outro,
  password,
  select,
  spinner,
  text,
} from "@clack/prompts";
import pc from "picocolors";
import type { KeyManagerService } from "../core/key-manager.ts";
import { SUPPORTED_ALGORITHMS, type SigningAlgorithm } from "../core/types.ts";
import {
  renderInspectReport,
  renderIntegrityReport,
  renderKeyTable,
  renderMutationDiff,
} from "./output.ts";

/**
 * Hỏi người dùng chọn 1 hoặc nhiều khóa để xóa an toàn (có hiển thị Diff Preview & hỏi xóa file .pem).
 */
export async function interactiveRemoveFlow(
  manager: KeyManagerService,
  preselectedKids?: string[],
  forceOption?: boolean
): Promise<void> {
  const allKeys = await manager.listKeys();
  if (allKeys.length === 0) {
    log.warn("Kho lưu trữ hiện đang trống, không có khóa nào để xóa.");
    return;
  }

  let selectedKids = preselectedKids ?? [];
  if (selectedKids.length === 0) {
    const picked = await multiselect({
      message:
        "Chọn 1 hoặc nhiều khóa cần xóa (Dùng phím Space để tích chọn, Enter để xác nhận):",
      options: allKeys.map((k) => ({
        value: k.kid,
        label: `${k.kid} [${k.alg}] — status: ${k.status}`,
        hint: k.status === "active" ? "ĐANG ACTIVE (Cẩn trọng!)" : `pem: ${k.privateKeyPath}`,
      })),
      required: true,
    });

    if (isCancel(picked)) {
      cancel("Đã hủy thao tác xóa khóa.");
      return;
    }
    selectedKids = picked as string[];
  }

  const hasActiveSelected = allKeys.some(
    (k) => selectedKids.includes(k.kid) && k.status === "active"
  );
  let allowForce = Boolean(forceOption);

  if (hasActiveSelected && !allowForce) {
    log.warn(
      pc.red(
        "CẢNH BÁO: Bạn đang chọn xóa khóa có trạng thái 'active' (đang dùng để ký JWT)!"
      )
    );
    const confirmActive = await confirm({
      message: "Bạn có thực sự chắc chắn muốn cưỡng bức xóa khóa đang 'active' này không?",
      initialValue: false,
    });
    if (isCancel(confirmActive) || !confirmActive) {
      cancel("Đã hủy thao tác để bảo vệ khóa đang active.");
      return;
    }
    allowForce = true;
  }

  const diffPreview = await manager.previewRemoveKeys(selectedKids, {
    force: allowForce,
  });
  note(renderMutationDiff(diffPreview), "Xem trước thay đổi (SafeMutationGuard)");

  const confirmDelete = await confirm({
    message: `Xác nhận xóa ${selectedKids.length} khóa đã chọn khỏi Store (còn lại ${diffPreview.afterCount} khóa được giữ nguyên 100%)?`,
    initialValue: false,
  });
  if (isCancel(confirmDelete) || !confirmDelete) {
    cancel("Đã hủy thao tác xóa khóa.");
    return;
  }

  const askDeletePem = await confirm({
    message: "Bạn có muốn xóa luôn file Private Key (.pem) tương ứng trên ổ đĩa không?",
    initialValue: false,
  });
  if (isCancel(askDeletePem)) {
    cancel("Đã hủy thao tác.");
    return;
  }

  const { diff, deletedPemPaths } = await manager.removeKeys(selectedKids, {
    force: allowForce,
    deletePrivateKeyFiles: Boolean(askDeletePem),
  });

  log.success(
    `Đã xóa an toàn ${diff.removed.length} khóa. Bảo toàn nguyên vẹn ${diff.afterCount} khóa còn lại.`
  );
  if (deletedPemPaths.length > 0) {
    log.info(`Đã xóa ${deletedPemPaths.length} file Private Key: ${deletedPemPaths.join(", ")}`);
  }
}

export async function runInteractiveWizard(
  manager: KeyManagerService,
  defaultPassphrase?: string
): Promise<void> {
  intro(pc.bgCyan(pc.black(" jwksctl — Trình Quản Lý JWKS Tương Tác ")));

  await manager.initStore();

  const action = await select({
    message: `Store hiện tại: ${pc.cyan(manager.adapter.location)} (${manager.adapter.kind}). Bạn muốn thực hiện thao tác nào?`,
    options: [
      { value: "list", label: "📋 Liệt kê danh sách khóa (list)" },
      { value: "generate", label: "✨ Tạo cặp khóa mới (generate)" },
      { value: "rotate", label: "🔄 Xoay vòng khóa an toàn (rotate)" },
      { value: "inspect", label: "🔍 Xem chi tiết khóa & SPKI PEM (inspect)" },
      { value: "remove", label: "🗑️  Xóa 1 hoặc nhiều khóa cùng lúc (remove)" },
      { value: "export", label: "📤 Xuất Public JWKS chuẩn RFC 7517 (export)" },
      { value: "check", label: "🛡️  Kiểm tra toàn vẹn Store & file .pem (check)" },
    ],
  });

  if (isCancel(action)) {
    cancel("Đã thoát trình tương tác.");
    return;
  }

  switch (action) {
    case "list": {
      const keys = await manager.listKeys();
      const pemMap = new Map<string, boolean>();
      for (const k of keys) {
        pemMap.set(k.kid, await manager.vault.exists(k.privateKeyPath));
      }
      console.log("\n" + renderKeyTable(keys, pemMap) + "\n");
      break;
    }

    case "generate": {
      const alg = await select({
        message: "Chọn thuật toán ký (alg):",
        options: SUPPORTED_ALGORITHMS.map((a) => ({
          value: a,
          label: a,
          hint:
            a === "EdDSA"
              ? "Ed25519 (Nhanh, khóa nhỏ, hiện đại)"
              : a === "ES256"
                ? "ECDSA P-256 (Phổ biến, gọn nhẹ)"
                : a === "RS256"
                  ? "RSA 2048-bit (Tương thích rộng nhất)"
                  : undefined,
        })),
        initialValue: "RS256" as SigningAlgorithm,
      });
      if (isCancel(alg)) {
        cancel("Đã hủy.");
        return;
      }

      const customKid = await text({
        message: "Nhập mã định danh khóa (kid) [Để trống để tự sinh theo chuẩn RFC 7638]:",
        placeholder: "Tự động (YYYY-MM-<thumbprint>)",
      });
      if (isCancel(customKid)) {
        cancel("Đã hủy.");
        return;
      }

      const wantEncrypt = await confirm({
        message: "Bạn có muốn mã hóa file Private Key (.pem) bằng AES-256-GCM không?",
        initialValue: Boolean(defaultPassphrase),
      });
      if (isCancel(wantEncrypt)) {
        cancel("Đã hủy.");
        return;
      }

      let passphrase = defaultPassphrase;
      if (wantEncrypt && !passphrase) {
        const entered = await password({
          message: "Nhập passphrase để mã hóa file Private Key (.pem):",
          validate: (val) => (!val || val.length < 4 ? "Passphrase cần ít nhất 4 ký tự" : undefined),
        });
        if (isCancel(entered)) {
          cancel("Đã hủy.");
          return;
        }
        passphrase = entered;
      }

      const s = spinner();
      s.start(`Đang sinh cặp khóa ${alg}...`);
      const { record, diff } = await manager.generateKey({
        alg: alg as SigningAlgorithm,
        kid: customKid ? String(customKid).trim() : undefined,
        passphrase: wantEncrypt ? passphrase : undefined,
      });
      s.stop(`Đã tạo thành công khóa "${pc.cyan(record.kid)}"!`);
      note(renderMutationDiff(diff), "Kết quả cập nhật Store");
      break;
    }

    case "rotate": {
      const grace = await text({
        message: "Thời gian ân hạn (Grace Period) cho khóa cũ ở trạng thái 'passive':",
        initialValue: "7d",
        placeholder: "7d (hoặc 24h, 30m)",
      });
      if (isCancel(grace)) {
        cancel("Đã hủy.");
        return;
      }

      const s = spinner();
      s.start("Đang xoay vòng khóa...");
      const { newRecord, demotedKids, diff } = await manager.rotateKeys({
        gracePeriod: String(grace || "7d"),
        passphrase: defaultPassphrase,
      });
      s.stop(
        `Đã xoay vòng khóa thành công! Khóa active mới: ${pc.green(newRecord.kid)} (Chuyển sang passive: ${demotedKids.join(", ") || "không có"})`
      );
      note(renderMutationDiff(diff), "Kết quả Rotate");
      break;
    }

    case "inspect": {
      const keys = await manager.listKeys();
      if (keys.length === 0) {
        log.warn("Chưa có khóa nào trong Store.");
        break;
      }
      const chosenKid = await select({
        message: "Chọn khóa cần xem chi tiết:",
        options: keys.map((k) => ({
          value: k.kid,
          label: `${k.kid} (${k.alg} - ${k.status})`,
        })),
      });
      if (isCancel(chosenKid)) {
        cancel("Đã hủy.");
        return;
      }
      const info = await manager.inspectKey(String(chosenKid));
      note(renderInspectReport(info), `Chi tiết khóa ${info.record.kid}`);
      break;
    }

    case "remove": {
      await interactiveRemoveFlow(manager);
      break;
    }

    case "export": {
      const exported = await manager.exportPublicJwks();
      console.log(JSON.stringify(exported, null, 2));
      break;
    }

    case "check": {
      const report = await manager.checkIntegrity();
      note(renderIntegrityReport(report, manager.adapter.location), "Báo cáo Toàn vẹn JWKS");
      break;
    }
  }

  outro(pc.dim("Hoàn tất thao tác."));
}
