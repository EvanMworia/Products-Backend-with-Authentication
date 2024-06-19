import jwt from 'jsonwebtoken';
import path from 'path';
import dotenv from 'dotenv';
dotenv.config({ path: path.resolve(__dirname, '../../.env') });
import { NextFunction, Request, Response } from 'express';
import { IPayload } from '../Models/authModels';

export interface IMiddlewareRequest extends Request {
    payloadInformation?: IPayload;
}
export function verifyToken(_request: IMiddlewareRequest, _response: Response, _next: NextFunction) {
    try {
        //READ THE TOKEN FIRST FROM THE HEADERS
        const token = _request.headers['token'] as string;
        //CHECK THE PRESCENCE OF THE TOKEN
        if (!token) {
            //IF TOKEN IS NOT PRESENT, THE REQUEST IS STOPPED AND THE USER IS FORBIDDEN FROM DOING WHAT THEY WERE TRYING
            return _response.status(401).json({ message: 'Forbiden!!!!!' });
        }
        //ELSE IF THE TOKEN WAS PRESENT CHECK THE VALIDITY OF IT.
        const decodedTokenData = jwt.verify(token, process.env.SECRET as string) as IPayload;
        _request.payloadInformation = decodedTokenData;
    } catch (error) {
        return _response.status(500).json(error);
    }

    //----------KEEEP IN MIND THAT ALL THIS WHILE THE REQUEST IS PAUSED, AFTER SUCCESSFUL READING AND VERIFICATION. WE SHOULD RELEASE IT TO CONTINUE.

    _next();
}
