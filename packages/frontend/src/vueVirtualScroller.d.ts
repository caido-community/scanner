declare module "vue-virtual-scroller" {
  import type { App, DefineComponent } from "vue";

  const plugin: {
    install: (app: App) => void;
  };

  export const RecycleScroller: DefineComponent<{
    items?: Array<unknown>;
    itemSize?: number;
    minItemSize?: number;
    keyField?: string;
  }>;

  export const DynamicScroller: DefineComponent<{
    items?: Array<unknown>;
    minItemSize?: number;
    keyField?: string;
  }>;

  export const DynamicScrollerItem: DefineComponent<{
    item?: unknown;
    active?: boolean;
    sizeDependencies?: Array<unknown>;
    dataIndex?: number;
    watchData?: boolean;
  }>;

  export default plugin;
}
