package com.afterlogic.crypto_plugin.pgp;

public  class PgpError extends Throwable {
    private final PgpErrorCase errorCase;

    PgpError(PgpErrorCase errorCase) {
        this.errorCase = errorCase;
    }

    public PgpErrorCase getErrorCase() {
        return errorCase;
    }
}
