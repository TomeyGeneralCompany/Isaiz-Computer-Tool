"use client";

import { Modal } from "./Modal";
import { StakeForm } from "./StakeForm";

export function StakeDialog({ onClose }: { onClose: () => void }) {
  return (
    <Modal title="Add Stake" onClose={onClose} showClose={false}>
      <StakeForm onSuccess={onClose} onCancel={onClose} />
    </Modal>
  );
}
