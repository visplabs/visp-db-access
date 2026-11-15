//! Statement classification and EXPLAIN execution semantics.
use crate::StatementKind;
use sqlparser::ast::{DescribeAlias, Expr, ObjectType, Statement, Value};

pub(crate) fn base(statement: &Statement) -> StatementKind {
    use StatementKind as K;
    match statement {
        Statement::Query(_) => K::Select,
        Statement::Explain { describe_alias, .. }
        | Statement::ExplainTable { describe_alias, .. } => {
            if matches!(describe_alias, DescribeAlias::Explain) {
                K::Explain
            } else {
                K::Show
            }
        }
        Statement::Insert(_) => K::Insert,
        Statement::Update(_) => K::Update,
        Statement::Delete(_) => K::Delete,
        Statement::Merge(_) => K::Merge,
        Statement::Grant(_)
        | Statement::Revoke(_)
        | Statement::Deny(_)
        | Statement::CreateRole(_)
        | Statement::AlterRole { .. }
        | Statement::CreateUser(_)
        | Statement::AlterUser(_) => K::Dcl,
        Statement::Drop {
            object_type: ObjectType::Role | ObjectType::User,
            ..
        } => K::Dcl,
        Statement::CreateView { .. }
        | Statement::CreateTable(_)
        | Statement::CreateVirtualTable { .. }
        | Statement::CreateIndex(_)
        | Statement::CreateSecret { .. }
        | Statement::CreateServer { .. }
        | Statement::CreatePolicy { .. }
        | Statement::CreateConnector { .. }
        | Statement::CreateOperator(_)
        | Statement::CreateOperatorFamily(_)
        | Statement::CreateOperatorClass(_)
        | Statement::CreateTextSearch(_)
        | Statement::CreateExtension { .. }
        | Statement::CreateCollation(_)
        | Statement::CreateSchema { .. }
        | Statement::CreateDatabase { .. }
        | Statement::CreateFunction(_)
        | Statement::CreateTrigger(_)
        | Statement::CreateProcedure { .. }
        | Statement::CreateMacro { .. }
        | Statement::CreateStage { .. }
        | Statement::CreateFileFormat { .. }
        | Statement::CreateWarehouse { .. }
        | Statement::CreateSequence { .. }
        | Statement::CreateDomain(_)
        | Statement::CreateType { .. }
        | Statement::AlterTable { .. }
        | Statement::AlterSchema(_)
        | Statement::AlterIndex { .. }
        | Statement::AlterView { .. }
        | Statement::AlterFunction { .. }
        | Statement::AlterType(_)
        | Statement::AlterCollation(_)
        | Statement::AlterOperator(_)
        | Statement::AlterOperatorFamily(_)
        | Statement::AlterOperatorClass(_)
        | Statement::AlterTextSearch(_)
        | Statement::AlterPolicy { .. }
        | Statement::AlterConnector { .. }
        | Statement::Drop { .. }
        | Statement::DropFunction { .. }
        | Statement::DropDomain { .. }
        | Statement::DropProcedure { .. }
        | Statement::DropSecret { .. }
        | Statement::DropPolicy { .. }
        | Statement::DropConnector { .. }
        | Statement::DropExtension { .. }
        | Statement::DropOperator(_)
        | Statement::DropOperatorFamily(_)
        | Statement::DropOperatorClass(_)
        | Statement::DropTrigger { .. }
        | Statement::Truncate { .. }
        | Statement::RenameTable(_)
        | Statement::Comment { .. } => K::Ddl,
        Statement::ShowFunctions { .. }
        | Statement::ShowVariable { .. }
        | Statement::ShowStatus { .. }
        | Statement::ShowVariables { .. }
        | Statement::ShowCreate { .. }
        | Statement::ShowColumns { .. }
        | Statement::ShowCatalogs { .. }
        | Statement::ShowDatabases { .. }
        | Statement::ShowProcessList { .. }
        | Statement::ShowSchemas { .. }
        | Statement::ShowCharset(_)
        | Statement::ShowObjects(_)
        | Statement::ShowTables { .. }
        | Statement::ShowViews { .. }
        | Statement::ShowCollation { .. } => K::Show,
        Statement::StartTransaction { .. }
        | Statement::Commit { .. }
        | Statement::Rollback { .. }
        | Statement::Savepoint { .. }
        | Statement::ReleaseSavepoint { .. } => K::Transaction,
        Statement::Analyze { .. }
        | Statement::Set(_)
        | Statement::Copy { .. }
        | Statement::CopyIntoSnowflake { .. }
        | Statement::Call(_)
        | Statement::Lock(_)
        | Statement::LockTables { .. }
        | Statement::Kill { .. }
        | Statement::Use(_)
        | Statement::LISTEN { .. }
        | Statement::UNLISTEN { .. }
        | Statement::NOTIFY { .. }
        | Statement::Prepare { .. }
        | Statement::Execute { .. }
        | Statement::Deallocate { .. }
        | Statement::Load { .. }
        | Statement::LoadData { .. }
        | Statement::Vacuum { .. }
        | Statement::Reset(_)
        | Statement::Discard { .. }
        | Statement::Declare { .. }
        | Statement::Fetch { .. }
        | Statement::Open { .. }
        | Statement::Close { .. }
        | Statement::Flush { .. }
        | Statement::Install { .. }
        | Statement::Directory { .. }
        | Statement::AlterSession { .. }
        | Statement::AttachDatabase { .. }
        | Statement::AttachDuckDBDatabase { .. }
        | Statement::DetachDuckDBDatabase { .. }
        | Statement::Cache { .. }
        | Statement::UNCache { .. }
        | Statement::Pragma { .. }
        | Statement::Unload { .. }
        | Statement::OptimizeTable { .. }
        | Statement::ExportData { .. }
        | Statement::List { .. }
        | Statement::Put { .. }
        | Statement::Remove { .. }
        | Statement::Case { .. }
        | Statement::If { .. }
        | Statement::While { .. } => K::Utility,
        _ => K::Other,
    }
}

pub(crate) fn is_write(kind: StatementKind) -> bool {
    matches!(
        kind,
        StatementKind::Insert
            | StatementKind::Update
            | StatementKind::Delete
            | StatementKind::Merge
    )
}

/// Whether EXPLAIN runs the statement. `ANALYSE` is PostgreSQL's synonym for
/// `ANALYZE`. Any executing option wins; only a literal `false` argument is
/// read as off, and every other argument (`true`, `on`, `off`, `0`, `1`,
/// strings) fails closed as executing.
pub(crate) fn explain_executes(statement: &Statement) -> bool {
    if let Statement::Explain {
        analyze, options, ..
    } = statement
    {
        *analyze
            || options.iter().flatten().any(|option| {
                is_analyze(&option.name.value)
                    && !matches!(&option.arg, Some(Expr::Value(v)) if matches!(v.value, Value::Boolean(false)))
            })
    } else {
        false
    }
}

fn is_analyze(word: &str) -> bool {
    word.eq_ignore_ascii_case("analyze") || word.eq_ignore_ascii_case("analyse")
}

pub(crate) fn is_plan_only(statement: &Statement) -> bool {
    matches!(statement, Statement::Explain { .. }) && !explain_executes(statement)
}
