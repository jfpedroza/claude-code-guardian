"""Tests for Engine class."""

from unittest.mock import Mock, patch

import pytest

from ccguardian.config import ConfigValidationError
from ccguardian.engine import Engine
from ccguardian.rules import Action, CommandPattern, PreUseBashRule, RuleResult
from tests.utils import post_use_write_context, pre_use_bash_context, session_start_context


class TestEngineInit:
    def test_init_stores_context(self):
        context = pre_use_bash_context("ls -la")
        engine = Engine(context)

        assert engine.context is context


class TestEngineRun:
    @patch("ccguardian.engine.exit_success")
    @patch("ccguardian.engine.ConfigurationManager")
    def test_run_session_start_context(self, mock_config_manager, mock_exit_success):
        context = session_start_context()

        mock_config = Mock()
        mock_config_manager.return_value.load_configuration.return_value = mock_config
        mock_exit_success.side_effect = SystemExit(0)

        engine = Engine(context)

        with pytest.raises(SystemExit):
            engine.run()

        mock_config_manager.assert_called_once()
        mock_config_manager.return_value.load_configuration.assert_called_once()
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.ConfigurationManager")
    def test_run_pre_tool_use_context(self, mock_config_manager):
        context = pre_use_bash_context("ls -la")

        mock_config = Mock()
        mock_config.active_rules = []
        mock_config_manager.return_value.load_configuration.return_value = mock_config

        engine = Engine(context)
        with patch.object(engine, "evaluate_rules", return_value=None) as mock_evaluate:
            with patch.object(engine, "handle_result") as mock_handle:
                engine.run()

                mock_evaluate.assert_called_once_with([])
                mock_handle.assert_called_once_with(None)

    @patch("ccguardian.engine.exit_success")
    def test_run_other_context_types(self, mock_exit_success):
        context = post_use_write_context("/tmp/test.txt")

        mock_exit_success.side_effect = SystemExit(0)

        engine = Engine(context)

        with pytest.raises(SystemExit):
            engine.run()

        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_non_block")
    @patch("ccguardian.engine.ConfigurationManager")
    def test_run_config_validation_error(self, mock_config_manager, mock_exit_non_block):
        context = pre_use_bash_context("ls -la")
        mock_config_manager.return_value.load_configuration.side_effect = ConfigValidationError(
            "Test error"
        )
        mock_exit_non_block.side_effect = SystemExit(0)

        engine = Engine(context)

        with pytest.raises(SystemExit):
            engine.run()

        mock_exit_non_block.assert_called_once_with(
            "Claude Code Guardian configuration error: Test error"
        )

    @patch("ccguardian.engine.exit_non_block")
    @patch("ccguardian.engine.ConfigurationManager")
    def test_run_general_exception(self, mock_config_manager, mock_exit_non_block):
        context = pre_use_bash_context("ls -la")
        mock_config_manager.return_value.load_configuration.side_effect = Exception(
            "General error"
        )
        mock_exit_non_block.side_effect = SystemExit(0)

        engine = Engine(context)

        with pytest.raises(SystemExit):
            engine.run()

        mock_exit_non_block.assert_called_once_with(
            "Claude Code Guardian hook failed: General error"
        )


class TestEngineEvaluateRules:
    def test_evaluate_rules_no_rules(self):
        context = pre_use_bash_context("ls -la")
        engine = Engine(context)

        result = engine.evaluate_rules([])

        assert result is None

    def test_evaluate_rules_no_matching_rules(self):
        context = pre_use_bash_context("ls -la")
        engine = Engine(context)

        rule = Mock()
        rule.evaluate.return_value = None

        result = engine.evaluate_rules([rule])

        assert result is None
        rule.evaluate.assert_called_once_with(context)

    def test_evaluate_rules_first_match_wins(self):
        context = pre_use_bash_context("grep test")
        engine = Engine(context)

        rule1 = Mock()
        rule1.id = "rule1"
        rule1_result = RuleResult(rule_id="rule1", action=Action.DENY, message="First rule")
        rule1.evaluate.return_value = rule1_result

        rule2 = Mock()
        rule2.id = "rule2"
        rule2_result = RuleResult(rule_id="rule2", action=Action.ALLOW, message="Second rule")
        rule2.evaluate.return_value = rule2_result

        result = engine.evaluate_rules([rule1, rule2])

        assert result is rule1_result
        rule1.evaluate.assert_called_once_with(context)
        rule2.evaluate.assert_not_called()

    def test_evaluate_rules_with_real_rule(self):
        context = pre_use_bash_context("grep test")
        engine = Engine(context)

        grep_rule = PreUseBashRule(
            id="performance.grep_suggestion",
            enabled=True,
            priority=50,
            commands=[
                CommandPattern(
                    pattern=r"^grep\b(?!.*\|)",
                    action=Action.DENY,
                    message="Use 'rg' instead",
                )
            ],
        )

        result = engine.evaluate_rules([grep_rule])

        assert result is not None
        assert result.action == Action.DENY
        assert result.message == "Use 'rg' instead"
        assert result.rule_id == "performance.grep_suggestion"


class TestEngineHandleResult:
    def setup_method(self):
        self.context = pre_use_bash_context("ls -la")
        self.engine = Engine(self.context)

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_none(self, mock_exit_success):
        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(None)

        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_allow(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.ALLOW, message="Test message")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        self.context.output.allow.assert_called_once()
        call_args = self.context.output.allow.call_args[0][0]
        assert "Guardian: Action allowed. Test message" in call_args
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_warn(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.WARN, message="Test warning")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        self.context.output.allow.assert_called_once()
        call_args = self.context.output.allow.call_args[1]  # system_message is keyword arg
        assert "Guardian: Test warning" in call_args["system_message"]
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_ask(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.ASK, message="Ask user")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        self.context.output.ask.assert_called_once()
        call_args = self.context.output.ask.call_args[0][0]
        assert "Guardian: Ask user" in call_args
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_deny(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.DENY, message="Denied")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        self.context.output.deny.assert_called_once()
        call_args = self.context.output.deny.call_args[0][0]
        assert "Guardian: Denied" in call_args
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_halt(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.HALT, message="Halt execution")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        self.context.output.halt.assert_called_once()
        call_args = self.context.output.halt.call_args[0][0]
        assert "Guardian: 🛑 Halting. Halt execution" in call_args
        mock_exit_success.assert_called_once()

    @patch("ccguardian.engine.exit_success")
    def test_handle_result_continue(self, mock_exit_success):
        result = RuleResult(rule_id="test.rule", action=Action.CONTINUE, message="Continue")

        mock_exit_success.side_effect = SystemExit(0)

        with pytest.raises(SystemExit):
            self.engine.handle_result(result)

        mock_exit_success.assert_called_once()
