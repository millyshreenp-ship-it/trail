use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWxTWqkZrUr5BBHQbKiL26VaR5K7");

#[program]
pub mod earlytrace_evidence {
    use super::*;

    pub fn publish_checkpoint(ctx: Context<PublishCheckpoint>, batch_id: [u8; 32], commitment: [u8; 32]) -> Result<()> {
        require!(batch_id != [0; 32] && commitment != [0; 32], EvidenceError::EmptyCommitment);
        let record = &mut ctx.accounts.checkpoint;
        record.issuer = ctx.accounts.issuer.key();
        record.batch_id = batch_id;
        record.commitment = commitment;
        record.created_at = Clock::get()?.unix_timestamp;
        record.bump = ctx.bumps.checkpoint;
        Ok(())
    }

    pub fn register_model(ctx: Context<RegisterModel>, artifact_hash: [u8; 32], feature_hash: [u8; 32], calibration_hash: [u8; 32]) -> Result<()> {
        require!(artifact_hash != [0; 32] && feature_hash != [0; 32], EvidenceError::EmptyCommitment);
        let record = &mut ctx.accounts.model;
        record.issuer = ctx.accounts.issuer.key();
        record.artifact_hash = artifact_hash;
        record.feature_hash = feature_hash;
        record.calibration_hash = calibration_hash;
        record.created_at = Clock::get()?.unix_timestamp;
        record.bump = ctx.bumps.model;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(batch_id: [u8; 32])]
pub struct PublishCheckpoint<'info> {
    #[account(mut)]
    pub issuer: Signer<'info>,
    #[account(init, payer = issuer, space = 8 + Checkpoint::INIT_SPACE, seeds = [b"checkpoint", issuer.key().as_ref(), batch_id.as_ref()], bump)]
    pub checkpoint: Account<'info, Checkpoint>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(artifact_hash: [u8; 32])]
pub struct RegisterModel<'info> {
    #[account(mut)]
    pub issuer: Signer<'info>,
    #[account(init, payer = issuer, space = 8 + ModelRecord::INIT_SPACE, seeds = [b"model", issuer.key().as_ref(), artifact_hash.as_ref()], bump)]
    pub model: Account<'info, ModelRecord>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Checkpoint {
    pub issuer: Pubkey,
    pub batch_id: [u8; 32],
    pub commitment: [u8; 32],
    pub created_at: i64,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct ModelRecord {
    pub issuer: Pubkey,
    pub artifact_hash: [u8; 32],
    pub feature_hash: [u8; 32],
    pub calibration_hash: [u8; 32],
    pub created_at: i64,
    pub bump: u8,
}

#[error_code]
pub enum EvidenceError {
    #[msg("Commitment identity must not be empty")]
    EmptyCommitment,
}