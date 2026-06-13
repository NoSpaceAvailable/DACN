import { Meteor } from 'meteor/meteor';
import { Notes } from './notes.js';

function sanitizeFilter(filter) {
    if (!filter || typeof filter !== 'object') return {};
    const out = {};
    for (const key of Object.keys(filter)) {
        if (key.startsWith('$')) continue;
        out[key] = filter[key];
    }
    return out;
}

Meteor.methods({
    'notes.count': function (filter) {
        return Notes.find(sanitizeFilter(filter)).count();
    },
    'notes.add': function () {
        const user = this.userId;
        if (!user) throw new Meteor.Error('not-authorized', 'You are not logged in.');
        return Notes.insert({
            body: '### Title\n\nNew note\n\nCreated at ' + (new Date()).toLocaleString(),
            owner: user,
        });
    },
    'notes.remove': function (id) {
        const user = this.userId;
        if (!user) throw new Meteor.Error('not-authorized', 'You are not logged in.');
        return Notes.remove({ _id: id, owner: this.userId });
    },
});
