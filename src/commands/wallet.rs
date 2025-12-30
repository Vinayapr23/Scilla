use {
    crate::{
        commands::CommandExec,
        context::ScillaContext,
        error::ScillaResult, misc::helpers::lamports_to_sol,
    },
    comfy_table::{Cell, Table, presets::UTF8_FULL},
    console::style,
    std::fmt,
};

/// Commands related to wallet context like address, balance, keypair path
#[derive(Debug, Clone)]
pub enum WalletCommand {
    Show,
    GoBack,
}

impl WalletCommand {
    pub fn spinner_msg(&self) -> &'static str {
        match self {
            WalletCommand::Show => "Fetching wallet summary…",
            WalletCommand::GoBack => "Going back…",
        }
    }
}

impl fmt::Display for WalletCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let command = match self {
            WalletCommand::Show => "Wallet Summary",
            WalletCommand::GoBack => "Go back",
        };
        write!(f, "{command}")
    }
}

impl WalletCommand {
    pub async fn process_command(&self, ctx: &ScillaContext) -> ScillaResult<()> {
        match self {
            WalletCommand::Show => show_wallet(ctx).await?,
            WalletCommand::GoBack => return Ok(CommandExec::GoBack),
        };

        Ok(CommandExec::Process(()))
    }
}

async fn show_wallet(ctx: &ScillaContext) -> anyhow::Result<()> {
    let pubkey = ctx.pubkey();
    let acc = ctx.rpc().get_account(&pubkey).await?;

    let balance_sol = lamports_to_sol(acc.lamports);

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_header(vec![
            Cell::new("Field").add_attribute(comfy_table::Attribute::Bold),
            Cell::new("Value").add_attribute(comfy_table::Attribute::Bold),
        ])
        .add_row(vec![Cell::new("Public Key"), Cell::new(pubkey.to_string())])
        .add_row(vec![Cell::new("Balance (SOL)"), Cell::new(format!("{balance_sol}"))])
        .add_row(vec![Cell::new("Lamports"), Cell::new(acc.lamports.to_string())])
        .add_row(vec![Cell::new("Owner"), Cell::new(acc.owner.to_string())])
        .add_row(vec![Cell::new("Executable"), Cell::new(acc.executable.to_string())])
        .add_row(vec![Cell::new("Rent Epoch"), Cell::new(acc.rent_epoch.to_string())]);

    println!("\n{}", style("WALLET").green().bold());
    println!("{table}");

    Ok(())
}