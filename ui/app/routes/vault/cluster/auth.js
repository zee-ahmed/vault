import { inject as service } from '@ember/service';
import ClusterRouteBase from './cluster-route-base';
import config from 'vault/config/environment';

export default ClusterRouteBase.extend({
  queryParams: {
    authMethod: {
      replace: true,
      refreshModel: true
    },
  },
  flashMessages: service(),
  version: service(),
  wizard: service(),
  beforeModel() {
    return this._super().then(() => {
      return this.get('version').fetchFeatures();
    });
  },
  model(params) {
    if (params.authMethod === 'google') {
        let controller = this.controllerFor(this.routeName)
        controller.set('callback', true);
        controller.set('mountPath', params.mount_path);
    }
    return this._super(...arguments);
  },
  resetController(controller) {
    controller.set('wrappedToken', '');
    controller.set('authMethod', '');
  },

  afterModel() {
    if (config.welcomeMessage) {
      this.get('flashMessages').stickyInfo(config.welcomeMessage);
    }
  },
  activate() {
    this.get('wizard').set('initEvent', 'LOGIN');
    this.get('wizard').transitionTutorialMachine(this.get('wizard.currentState'), 'TOLOGIN');
  },
  actions: {
    willTransition(transition) {
      if (transition.targetName !== this.routeName) {
        this.get('wizard').transitionTutorialMachine(this.get('wizard.currentState'), 'INITDONE');
      }
    },
  },
});
