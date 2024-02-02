import mongoose from "mongoose";
import bcrypt from "bcrypt";

export type DeviceDocument = mongoose.Document & {
    SerialNumber: string;
    SecretKey: string;
};

const deviceSchema = new mongoose.Schema<DeviceDocument>(
    {
        SerialNumber: { type: String, unique: true },
        SecretKey: String
    },
    { timestamps: true },
);

/**
 * Token encryption middleware.
 */
deviceSchema.pre("save", function save(next) {
    const user = this as DeviceDocument;
    if (!user.isModified("password")) {
        return next();
    }
    bcrypt.genSalt(10, (err, salt) => {
        if (err) { return next(err); }
        bcrypt.hash(user.password, salt, undefined, (err: mongoose.Error, hash) => {
            if (err) { return next(err); }
            user.password = hash;
            next();
        });
    });
});

export const Device = mongoose.model<DeviceDocument>("Device", deviceSchema);
