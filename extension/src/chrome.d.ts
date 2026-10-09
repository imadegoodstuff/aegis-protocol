// The slice of the extensions API this code touches. Kept here instead of
// pulling @types/chrome into the wallet's dependency tree.
declare namespace chrome {
  namespace storage {
    interface Area {
      get(key: string): Promise<Record<string, unknown>>;
      set(items: Record<string, unknown>): Promise<void>;
      remove(key: string): Promise<void>;
    }
    const local: Area;
  }
  namespace runtime {
    const onInstalled: { addListener(cb: () => void): void };
    function getURL(path: string): string;
  }
  namespace sidePanel {
    function setPanelBehavior(opts: { openPanelOnActionClick: boolean }): Promise<void>;
    function open(opts: { windowId: number }): Promise<void>;
  }
  namespace action {
    const onClicked: { addListener(cb: (tab: { windowId?: number }) => void): void };
  }
  namespace tabs {
    function create(opts: { url: string }): Promise<unknown>;
  }
}
