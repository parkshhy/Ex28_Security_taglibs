import React, { Component } from 'react';
import { Grid, Cell, ProgressBar } from 'react-mdl';

class Skills extends Component {
    render() {
        return (
            <Grid>

                <Cell col={4}>
                    <div>
                        <p>{this.props.skills}</p>
                    </div>
                </Cell>
                <Cell col={4}>
                    <div>
                        <ProgressBar style={{ margin: 'auto', width: "100%" }}
                            progress={this.props.progress} 
                            buffer={this.props.buffer}/></div>
                </Cell>
            </Grid>
        )
    }
}
export default Skills;