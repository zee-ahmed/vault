import { inject as service } from '@ember/service';
import { alias } from '@ember/object/computed';
import { computed } from '@ember/object';
import Controller, { inject as controller } from '@ember/controller';
import { task, timeout } from 'ember-concurrency';

export default Controller.extend({
  vaultController: controller('vault'),
  clusterController: controller('vault.cluster'),
  namespaceService: service('namespace'),
  namespaceQueryParam: alias('clusterController.namespaceQueryParam'),
  queryParams: [
      { authMethod: 'with' },
      { callbackState: 'state'},
      { callbackScope: 'scope'},
      { callbackCode: 'code'},
  ],
  wrappedToken: alias('vaultController.wrappedToken'),
  authMethod: '',
  redirectTo: alias('vaultController.redirectTo'),
  callback: false,
  callbackState: null,
  callbackScope: null,
  callbackCode: null,
  mountPath: null,

  callbackInfo: computed(function() {
      if (! this.get('callback')) {
        return null;
      }
      return {
          mountPath: this.get('mountPath'),
          state: this.get('callbackState'),
          scope: this.get('callbackScope'),
          code: this.get('callbackCode'),
      };
  }),

  updateNamespace: task(function*(value) {
    // debounce
    yield timeout(500);
    this.get('namespaceService').setNamespace(value, true);
    this.set('namespaceQueryParam', value);
  }).restartable(),
});
