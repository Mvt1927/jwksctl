import {
  FORBIDDEN_PRIVATE_JWK_FIELDS,
  type JwkRecord,
  type MutationDiff,
} from "./types.ts";

export class SecurityViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SecurityViolationError";
  }
}

export class IntegrityViolationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IntegrityViolationError";
  }
}

export class ActiveKeyDeletionError extends Error {
  constructor(public readonly activeKids: string[]) {
    super(
      `Chặn xóa nhầm: Các khóa [${activeKids.join(", ")}] đang ở trạng thái "active". Vui lòng rotate khóa trước hoặc truyền cờ --force nếu thực sự muốn xóa.`
    );
    this.name = "ActiveKeyDeletionError";
  }
}

function stableRecordSerialize(record: JwkRecord): string {
  const sortedEntries = Object.entries(record).sort(([a], [b]) => a.localeCompare(b));
  return JSON.stringify(Object.fromEntries(sortedEntries));
}

export class SafeMutationGuard {
  /**
   * Đảm bảo tuyệt đối không có bất kỳ tham số khóa bí mật nào lọt vào bản ghi JwkRecord.
   */
  static assertNoPrivateMaterial(records: readonly JwkRecord[]): void {
    for (const rec of records) {
      const raw = rec as unknown as Record<string, unknown>;
      for (const field of FORBIDDEN_PRIVATE_JWK_FIELDS) {
        if (field in raw && raw[field] !== undefined) {
          throw new SecurityViolationError(
            `Vi phạm bảo mật: Phát hiện trường khóa bí mật "${field}" trong key "${rec.kid}". Store chỉ được phép lưu Public JWK và privateKeyPath.`
          );
        }
      }
      if (!rec.privateKeyPath || typeof rec.privateKeyPath !== "string") {
        throw new IntegrityViolationError(
          `Bản ghi key "${rec.kid}" thiếu đường dẫn "privateKeyPath" hợp lệ.`
        );
      }
    }
  }

  /**
   * Đảm bảo danh sách key không có `kid` trùng lặp.
   */
  static assertUniqueKids(records: readonly JwkRecord[]): void {
    const seen = new Set<string>();
    for (const rec of records) {
      if (!rec.kid || typeof rec.kid !== "string") {
        throw new IntegrityViolationError("Phát hiện bản ghi JWK thiếu định danh 'kid'.");
      }
      if (seen.has(rec.kid)) {
        throw new IntegrityViolationError(
          `Vi phạm toàn vẹn dữ liệu: Trùng lặp mã định danh kid "${rec.kid}".`
        );
      }
      seen.add(rec.kid);
    }
  }

  /**
   * Kiểm tra bất biến khi THÊM MỚI (CREATE):
   * - 100% key cũ trong `before` phải còn nguyên vẹn tuyệt đối trong `after`.
   * - Chỉ đúng các `expectedAddedKids` mới được phép xuất hiện thêm.
   */
  static verifyCreateInvariant(
    before: readonly JwkRecord[],
    after: readonly JwkRecord[],
    expectedAddedKids: readonly string[]
  ): void {
    SafeMutationGuard.assertNoPrivateMaterial(after);
    SafeMutationGuard.assertUniqueKids(after);

    const beforeMap = new Map(before.map((k) => [k.kid, k]));
    const afterMap = new Map(after.map((k) => [k.kid, k]));

    for (const [kid, oldKey] of beforeMap.entries()) {
      const afterKey = afterMap.get(kid);
      if (!afterKey) {
        throw new IntegrityViolationError(
          `Chặn mất key khi CREATE: Khóa cũ "${kid}" bị mất khỏi danh sách sau khi thêm mới!`
        );
      }
      if (stableRecordSerialize(oldKey) !== stableRecordSerialize(afterKey)) {
        throw new IntegrityViolationError(
          `Chặn ghi đè nhầm khi CREATE: Khóa cũ "${kid}" bị thay đổi nội dung ngoài ý muốn!`
        );
      }
    }

    const expectedSet = new Set(expectedAddedKids);
    if (after.length !== before.length + expectedSet.size) {
      throw new IntegrityViolationError(
        `Sai lệch số lượng key khi CREATE: Trước=${before.length}, Cần thêm=${expectedSet.size}, Sau=${after.length}.`
      );
    }

    for (const addedKid of expectedSet) {
      if (!afterMap.has(addedKid)) {
        throw new IntegrityViolationError(
          `Khóa mới "${addedKid}" không tìm thấy trong danh sách sau khi CREATE.`
        );
      }
    }
  }

  /**
   * Kiểm tra bất biến khi CẬP NHẬT (UPDATE):
   * - Không có bất kỳ key nào bị mất đi hoặc thêm mới.
   * - Các key KHÔNG nằm trong `targetKids` phải giữ nguyên 100% từng byte.
   */
  static verifyUpdateInvariant(
    before: readonly JwkRecord[],
    after: readonly JwkRecord[],
    targetKids: readonly string[]
  ): void {
    SafeMutationGuard.assertNoPrivateMaterial(after);
    SafeMutationGuard.assertUniqueKids(after);

    if (before.length !== after.length) {
      throw new IntegrityViolationError(
        `Chặn mất key khi UPDATE: Số lượng key thay đổi từ ${before.length} thành ${after.length}.`
      );
    }

    const beforeMap = new Map(before.map((k) => [k.kid, k]));
    const afterMap = new Map(after.map((k) => [k.kid, k]));
    const targetSet = new Set(targetKids);

    for (const [kid, oldKey] of beforeMap.entries()) {
      const newKey = afterMap.get(kid);
      if (!newKey) {
        throw new IntegrityViolationError(
          `Chặn mất key khi UPDATE: Khóa "${kid}" bị rơi khỏi danh sách!`
        );
      }
      if (!targetSet.has(kid)) {
        if (stableRecordSerialize(oldKey) !== stableRecordSerialize(newKey)) {
          throw new IntegrityViolationError(
            `Chặn sửa nhầm khi UPDATE: Khóa "${kid}" không nằm trong danh sách cập nhật nhưng bị thay đổi dữ liệu!`
          );
        }
      }
    }
  }

  /**
   * Kiểm tra bất biến khi XÓA (DELETE 1 hoặc nhiều key):
   * - Chặn xóa khóa đang `active` nếu không có `force: true`.
   * - Đảm bảo mọi khóa KHÔNG nằm trong `targetKidsToDelete` phải còn nguyên vẹn 100%.
   */
  static verifyDeleteInvariant(
    before: readonly JwkRecord[],
    after: readonly JwkRecord[],
    targetKidsToDelete: readonly string[],
    options: { force?: boolean } = {}
  ): void {
    SafeMutationGuard.assertNoPrivateMaterial(after);
    SafeMutationGuard.assertUniqueKids(after);

    const targetSet = new Set(targetKidsToDelete);
    if (targetSet.size === 0) {
      throw new IntegrityViolationError("Danh sách mã khóa (kid) cần xóa đang rỗng.");
    }

    const beforeMap = new Map(before.map((k) => [k.kid, k]));
    const afterMap = new Map(after.map((k) => [k.kid, k]));

    // Kiểm tra các kid yêu cầu xóa có tồn tại không
    for (const kid of targetSet) {
      if (!beforeMap.has(kid)) {
        throw new IntegrityViolationError(
          `Không tìm thấy khóa có kid "${kid}" trong kho lưu trữ để xóa.`
        );
      }
    }

    // Chặn xóa nhầm khóa đang active
    const activeTargets = before
      .filter((k) => targetSet.has(k.kid) && k.status === "active")
      .map((k) => k.kid);

    if (activeTargets.length > 0 && !options.force) {
      throw new ActiveKeyDeletionError(activeTargets);
    }

    // Kiểm tra mọi khóa không thuộc targetSet phải còn nguyên 100%
    for (const [kid, oldKey] of beforeMap.entries()) {
      if (targetSet.has(kid)) {
        if (afterMap.has(kid)) {
          throw new IntegrityViolationError(`Khóa "${kid}" đáng lẽ phải được xóa nhưng vẫn tồn tại.`);
        }
      } else {
        const remainingKey = afterMap.get(kid);
        if (!remainingKey) {
          throw new IntegrityViolationError(
            `Chặn xóa nhầm: Khóa "${kid}" KHÔNG nằm trong danh sách chọn xóa nhưng đã bị mất!`
          );
        }
        if (stableRecordSerialize(oldKey) !== stableRecordSerialize(remainingKey)) {
          throw new IntegrityViolationError(
            `Chặn hỏng dữ liệu khi DELETE: Khóa giữ lại "${kid}" bị thay đổi nội dung ngoài ý muốn!`
          );
        }
      }
    }

    if (after.length !== before.length - targetSet.size) {
      throw new IntegrityViolationError(
        `Sai lệch số lượng key sau khi DELETE: Trước=${before.length}, Cần xóa=${targetSet.size}, Sau=${after.length}.`
      );
    }
  }

  /**
   * Tính toán bảng đối chiếu (Diff Preview) giữa trạng thái trước và sau khi biến đổi.
   */
  static computeDiff(
    before: readonly JwkRecord[],
    after: readonly JwkRecord[]
  ): MutationDiff {
    const beforeMap = new Map(before.map((k) => [k.kid, k]));
    const afterMap = new Map(after.map((k) => [k.kid, k]));

    const added: JwkRecord[] = [];
    const updated: Array<{ before: JwkRecord; after: JwkRecord }> = [];
    const removed: JwkRecord[] = [];
    let unchangedCount = 0;

    for (const [kid, afterRec] of afterMap.entries()) {
      const beforeRec = beforeMap.get(kid);
      if (!beforeRec) {
        added.push(afterRec);
      } else if (stableRecordSerialize(beforeRec) !== stableRecordSerialize(afterRec)) {
        updated.push({ before: beforeRec, after: afterRec });
      } else {
        unchangedCount++;
      }
    }

    for (const [kid, beforeRec] of beforeMap.entries()) {
      if (!afterMap.has(kid)) {
        removed.push(beforeRec);
      }
    }

    const activeKeysRemoved = removed.filter((k) => k.status === "active");

    return {
      beforeCount: before.length,
      afterCount: after.length,
      added,
      updated,
      removed,
      unchangedCount,
      activeKeysRemoved,
    };
  }
}
