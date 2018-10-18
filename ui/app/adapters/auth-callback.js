import ApplicationAdapter from './application';

export default ApplicationAdapter.extend({
  callbackAction(backend, callback) {
    let url = '/v1/auth/google/login';
    let options = {
      unauthenticated: true,
      data: {
        state: callback.state,
        role: 'hello',
        code: callback.code,
      }
    };
    return this.ajax(url, 'POST', options);
  },
});
