import type { JwkRecord, MutationDiff } from "../core/types.ts";

export interface RemoveKeysOptions {
	force?: boolean;
}

export interface IStorageAdapter {
	readonly kind: string;
	readonly location: string;

	/** Khởi tạo file hoặc bảng Database nếu chưa tồn tại */
	init(): Promise<void>;

	/** Lấy toàn bộ danh sách khóa trong Store */
	listKeys(): Promise<JwkRecord[]>;

	/** Tìm 1 khóa theo kid */
	getKey(kid: string): Promise<JwkRecord | null>;

	/** Thêm 1 hoặc nhiều khóa mới (có kiểm tra bất biến CREATE) */
	addKeys(newRecords: readonly JwkRecord[]): Promise<MutationDiff>;

	/** Cập nhật 1 hoặc nhiều khóa hiện có (có kiểm tra bất biến UPDATE) */
	updateKeys(updatedRecords: readonly JwkRecord[]): Promise<MutationDiff>;

	/**
	 * Xoay vòng khóa nguyên tử (Atomic Rotate):
	 * Cập nhật các khóa cũ sang `passive` (hoặc `revoked`) và thêm khóa `active` mới trong cùng 1 giao dịch.
	 */
	rotateAtomic(
		updatedOldRecords: readonly JwkRecord[],
		newActiveRecord: JwkRecord,
	): Promise<MutationDiff>;

	/** Xóa 1 hoặc nhiều khóa theo danh sách kid (có kiểm tra bất biến DELETE & chặn xóa nhầm active) */
	removeKeys(kidsToRemove: readonly string[], options?: RemoveKeysOptions): Promise<MutationDiff>;

	/** Xem trước Diff nếu thực hiện xóa danh sách kid này (không ghi xuống đĩa/DB) */
	previewRemoveKeys(
		kidsToRemove: readonly string[],
		options?: RemoveKeysOptions,
	): Promise<MutationDiff>;

	/** Khôi phục dữ liệu từ bản sao lưu .bak gần nhất (nếu Adapter hỗ trợ) */
	restoreBackup?(): Promise<JwkRecord[]>;

	/** Đóng kết nối (nếu có) */
	close?(): Promise<void>;
}
