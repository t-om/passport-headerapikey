/**
 *  Creator: Christian Hotz
 *  Company: hydra newmedia GmbH
 *  Date: 27.06.16
 *
 *  Copyright hydra newmedia GmbH
 */

import { Request } from 'express';
import { Strategy as PassportStrategy } from 'passport-strategy';
import { BadRequestError } from './errors/BadRequestError';

interface Options {
    header: string
    prefix?: string,
    name?: string
};

type Verify = (apiKey: string, done: (err: Error | null, user?: Object, info?: Object) => void, req?: Request) => void;

export class Strategy extends PassportStrategy {

    options: Options;
    name: string;
    verify: Verify;
    passReqToCallback: boolean;

    constructor(options: Options, passReqToCallback: boolean, verify: Verify) {
        super();

        this.options = options || { header: "X-Api-Key" };
        if (!this.options.header) this.options.header = "X-Api-Key";
        if (!this.options.prefix) this.options.prefix = "";
        if (!this.options.name) this.options.name = "headerapikey";
        this.options.header = this.options.header.toLowerCase();

        this.name = this.options.name;
        this.verify = verify;
        this.passReqToCallback = passReqToCallback || false;
    };

    authenticate(req: Request): void {
        const { header, prefix } = this.options;

        let apiKey: string = req.headers[header] as string;
        if (!apiKey) return this.fail(new BadRequestError("Missing API Key"), null);

        if (apiKey.startsWith(prefix)) apiKey = apiKey.replace(new RegExp('^' + prefix), '');
        else return this.fail(new BadRequestError(`Invalid API Key prefix, ${header} header should start with "${prefix}"`), null);

        const verified = (err: Error | null, user?: Object, info?: Object) => {
            if (err) return this.error(err);
            if (!user) return this.fail(info, null);
            this.success(user, info);
        };

        const optionalCallbackParams = [  ];
        if (this.passReqToCallback) optionalCallbackParams.push(req);
        this.verify(apiKey, verified, ...optionalCallbackParams);
    };

};