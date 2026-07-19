//go:build !linux

package filesecurity

func (m *ManagedRoots) InventoryManagedTransferTransactions(parentPath string) (ManagedTransferInventoryResult, error) {
	return ManagedTransferInventoryResult{Parent: parentPath, Items: []ManagedTransferInventoryItem{}}, ErrManagedRootsUnsupported
}
