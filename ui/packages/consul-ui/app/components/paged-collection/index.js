import Component from '@glimmer/component';
import { inject as service } from '@ember/service';
import { action } from '@ember/object';
import { tracked } from '@glimmer/tracking';

let guid = 0;
export default class PagedCollectionComponent extends Component {
  @tracked $pane;
  @tracked rect = { y: 0 };
  @tracked visibleItems;
  @tracked overflow = 10;

  constructor() {
    super(...arguments);
    this.guid = ++guid;
  }

  get type() {
    return this.args.type || 'native-scroll';
  }

  get perPage() {
    switch (this.type) {
      case 'virtual-scroll':
        return Math.max(0, this.visibleItems + this.overflow * 2);
      case 'index':
        return parseInt(this.args.perPage);
      case 'native-scroll':
        return this.total;
    }
  }

  get total() {
    return this.args.items.length;
  }

  get cursor() {
    switch (this.type) {
      case 'virtual-scroll':
        return Math.max(0, this.itemsBefore - this.overflow);
      case 'index':
        return (parseInt(this.args.page) - 1) * this.perPage;
      case 'native-scroll':
        return 0;
    }
  }

  get items() {
    return this.args.items.slice(this.cursor, Math.min(this.total, this.cursor + this.perPage));
  }

  get rowHeight() {
    return parseInt(this.args.rowHeight || 70);
  }

  get startHeight() {
    return this.cursor * this.rowHeight;
  }

  get endHeight() {
    return this.itemsAfter * this.rowHeight;
  }

  get totalHeight() {
    return this.startHeight + this.perPage * this.rowHeight + this.endHeight;
  }

  get itemsBefore() {
    let items = 0;
    if (this.rect.y < 0) {
      items = Math.floor(-this.rect.y / this.rowHeight);
    }
    return items;
  }

  get itemsAfter() {
    return this.total - this.perPage - this.cursor;
  }

  @action
  scroll() {
    this.rect = this.$pane.getBoundingClientRect();
    if (false) {
      this.$pane.style.position = 'relative';
      this.$child.style.position = 'absolute';
      this.$child.style.top = '0';
      this.$child.style.transform = `translate3d(0, ${this.startHeight}px, 0)`;
    }
  }

  @action
  resize() {
    this.visibleItems = Math.ceil(this.$viewport.clientHeight / this.rowHeight);
  }

  @action
  connect($meta) {
    this.$viewport = [...document.getElementsByTagName('html')][0];
    this.$pane = $meta.nextElementSibling;
    this.$pane.setAttribute(`data-collection-${this.guid}`, '');
    // this.$child = this.$pane.firstElementChild;
    window.addEventListener('scroll', this.scroll);
    window.addEventListener('resize', this.resize);
    this.scroll();
    this.resize();
  }
  @action
  disconnect() {
    window.removeEventListener('scroll', this.scroll);
    window.removeEventListener('resize', this.resize);
  }
}
