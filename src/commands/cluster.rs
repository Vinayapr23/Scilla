use {
    crate::{
        commands::CommandExec, constants::LAMPORTS_PER_SOL, context::ScillaContext,
        error::ScillaResult, ui::show_spinner,
    },
    console::style,
    std::ops::Div,
};

/// Commands related to cluster operations
#[derive(Debug, Clone)]
pub enum ClusterCommand {
    Epoch,
    Slot,
    BlockHeight,
    BlockTime,
    Validators,
    Supply,
    Inflation,
    ClusterVersion,
    GoBack,
}

impl ClusterCommand {
    pub fn description(&self) -> &'static str {
        match self {
            ClusterCommand::Epoch => "Get Epoch Info",
            ClusterCommand::Slot => "Get Current Slot",
            ClusterCommand::BlockHeight => "Get Block Height",
            ClusterCommand::BlockTime => "Get Block Time",
            ClusterCommand::Validators => "Get Validators",
            ClusterCommand::Supply => "Get Supply Info",
            ClusterCommand::Inflation => "Get Inflation Info",
            ClusterCommand::ClusterVersion => "Get Cluster Version",
            ClusterCommand::GoBack => "Go back",
        }
    }
}

impl ClusterCommand {
    pub async fn process_command(&self, ctx: &ScillaContext) -> ScillaResult<()> {
        match self {
            ClusterCommand::Epoch => {
                show_spinner(self.description(), fetch_epoch_info(ctx)).await?;
            }
            ClusterCommand::Slot => {
                show_spinner(self.description(), fetch_current_slot(ctx)).await?;
            }
            ClusterCommand::BlockHeight => {
                show_spinner(self.description(), fetch_block_height(ctx)).await?;
            }
            ClusterCommand::BlockTime => {
                show_spinner(self.description(), fetch_block_time(ctx)).await?;
            }
            ClusterCommand::Validators => {
                show_spinner(self.description(), fetch_validators(ctx)).await?;
            }
            ClusterCommand::Supply => {
                show_spinner(self.description(), fetch_supply_info(ctx)).await?;
            }
            ClusterCommand::Inflation => {
                show_spinner(self.description(), fetch_inflation_info(ctx)).await?;
            }
            ClusterCommand::ClusterVersion => {
                show_spinner(self.description(), fetch_cluster_version(ctx)).await?;
            }
            ClusterCommand::GoBack => {
                return Ok(CommandExec::GoBack);
            }
        };

        Ok(CommandExec::Process(()))
    }
}

async fn fetch_epoch_info(ctx: &ScillaContext) -> anyhow::Result<()> {
    let epoch_info = ctx.rpc().get_epoch_info().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           EPOCH INFORMATION").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Epoch:").yellow().bold(),
        style(format!("{}", epoch_info.epoch)).cyan()
    );
    println!(
        "  {} {}",
        style("Slot Index:").yellow().bold(),
        style(format!("{}", epoch_info.slot_index)).cyan()
    );
    println!(
        "  {} {}",
        style("Slots in Epoch:").yellow().bold(),
        style(format!("{}", epoch_info.slots_in_epoch)).cyan()
    );
    println!(
        "  {} {}",
        style("Absolute Slot:").yellow().bold(),
        style(format!("{}", epoch_info.absolute_slot)).cyan()
    );
    println!(
        "  {} {}",
        style("Block Height:").yellow().bold(),
        style(format!("{}", epoch_info.block_height)).cyan()
    );
    println!(
        "  {} {}",
        style("Transaction Count:").yellow().bold(),
        style(format!("{}", epoch_info.transaction_count.unwrap_or(0))).cyan()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_current_slot(ctx: &ScillaContext) -> anyhow::Result<()> {
    let slot = ctx.rpc().get_slot().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           CURRENT SLOT").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Slot:").yellow().bold(),
        style(format!("{}", slot)).cyan().bold()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_block_height(ctx: &ScillaContext) -> anyhow::Result<()> {
    let block_height = ctx.rpc().get_block_height().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           BLOCK HEIGHT").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Block Height:").yellow().bold(),
        style(format!("{}", block_height)).cyan().bold()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_block_time(ctx: &ScillaContext) -> anyhow::Result<()> {
    let slot = ctx.rpc().get_slot().await?;
    let block_time = ctx.rpc().get_block_time(slot).await?;

    let datetime = chrono::DateTime::<chrono::Utc>::from_timestamp_secs(block_time)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
        .unwrap_or_else(|| "Invalid timestamp".to_string());

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           BLOCK TIME").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Slot:").yellow().bold(),
        style(format!("{}", slot)).cyan()
    );
    println!(
        "  {} {}",
        style("Unix Timestamp:").yellow().bold(),
        style(format!("{}", block_time)).cyan()
    );
    println!(
        "  {} {}",
        style("Date/Time:").yellow().bold(),
        style(datetime).cyan().bold()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_validators(ctx: &ScillaContext) -> anyhow::Result<()> {
    let validators = ctx.rpc().get_vote_accounts().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           VALIDATORS").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Current Validators:").yellow().bold(),
        style(format!("{}", validators.current.len())).cyan().bold()
    );
    println!(
        "  {} {}",
        style("Delinquent Validators:").yellow().bold(),
        style(format!("{}", validators.delinquent.len()))
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    if !validators.current.is_empty() {
        println!("\n{}", style("Top Current Validators:").yellow().bold());
        println!("{}", style("───────────────────────────────────────").dim());
        for (idx, validator) in validators.current.iter().take(10).enumerate() {
            let stake_sol = (validator.activated_stake as f64).div(LAMPORTS_PER_SOL as f64);
            println!(
                "  {}. {}",
                style(format!("{}", idx + 1)).dim(),
                style(validator.node_pubkey.clone()).cyan()
            );
            println!(
                "     {} {} SOL",
                style("Stake:").dim(),
                style(format!("{:.2}", stake_sol)).cyan()
            );
            println!(
                "     {} {}",
                style("Vote Account:").dim(),
                style(validator.vote_pubkey.clone()).dim()
            );
            if idx < 9 && idx < validators.current.len() - 1 {
                println!();
            }
        }
        if validators.current.len() > 10 {
            println!(
                "\n  {}",
                style(format!(
                    "... and {} more validators",
                    validators.current.len() - 10
                ))
                .dim()
            );
        }
    }

    Ok(())
}

async fn fetch_supply_info(ctx: &ScillaContext) -> anyhow::Result<()> {
    let supply = ctx.rpc().supply().await?;

    let total_sol = (supply.value.total as f64).div(LAMPORTS_PER_SOL as f64);
    let circulating_sol = (supply.value.circulating as f64).div(LAMPORTS_PER_SOL as f64);
    let non_circulating_sol = (supply.value.non_circulating as f64).div(LAMPORTS_PER_SOL as f64);

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           SUPPLY INFORMATION").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {} SOL",
        style("Total Supply:").yellow().bold(),
        style(format!("{:.2}", total_sol)).cyan().bold()
    );
    println!(
        "  {} {} SOL",
        style("Circulating:").yellow().bold(),
        style(format!("{:.2}", circulating_sol)).cyan()
    );
    println!(
        "  {} {} SOL",
        style("Non-Circulating:").yellow().bold(),
        style(format!("{:.2}", non_circulating_sol)).cyan()
    );
    println!(
        "  {} {}",
        style("Circulating Percentage:").yellow().bold(),
        style(format!("{:.2}%", (circulating_sol / total_sol) * 100.0)).cyan()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_inflation_info(ctx: &ScillaContext) -> anyhow::Result<()> {
    let inflation = ctx.rpc().get_inflation_rate().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "{}",
        style("           INFLATION INFORMATION").green().bold()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Epoch:").yellow().bold(),
        style(format!("{}", inflation.epoch)).cyan()
    );
    println!(
        "  {} {}",
        style("Total Inflation Rate:").yellow().bold(),
        style(format!("{:.4}%", inflation.total * 100.0))
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Validator Inflation:").yellow().bold(),
        style(format!("{:.4}%", inflation.validator * 100.0)).cyan()
    );
    println!(
        "  {} {}",
        style("Foundation Inflation:").yellow().bold(),
        style(format!("{:.4}%", inflation.foundation * 100.0)).cyan()
    );
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}

async fn fetch_cluster_version(ctx: &ScillaContext) -> anyhow::Result<()> {
    let version = ctx.rpc().get_version().await?;

    println!(
        "\n{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!("{}", style("           CLUSTER VERSION").green().bold());
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );
    println!(
        "  {} {}",
        style("Solana Core:").yellow().bold(),
        style(version.solana_core.clone()).cyan().bold()
    );
    if let Some(feature_set) = version.feature_set {
        println!(
            "  {} {}",
            style("Feature Set:").yellow().bold(),
            style(format!("{}", feature_set)).cyan()
        );
    }
    println!(
        "{}",
        style("═══════════════════════════════════════")
            .cyan()
            .bold()
    );

    Ok(())
}
